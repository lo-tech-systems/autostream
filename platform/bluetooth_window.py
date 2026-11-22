#!/usr/bin/python3
"""bluetooth_window.py

Copyright (c) 2026 Lo-tech Systems Limited. All rights reserved.

The pairing window machine for the autostream_bluetooth daemon. While the
window is open the appliance is discoverable and pairable and discovery is
running, so a source that searches for a sink and a source found by
scanning both end up in one list; nothing pairs for audio until the user
taps an entry. The window lives only while someone is on the pairing screen
(its poll is the heartbeat) and never longer than ``WINDOW_LIMIT_S``.

Pure: it holds the state, the window's timestamps and the device list
(``bluetooth_devices.DeviceList``), and answers each event with an
``Outcome``: an optional reply code for the socket and the actions the
service must run (adapter writes, discovery, ops). Time is passed in with
every event; nothing here touches D-Bus, BlueZ, sockets or the pump.

``_TABLE`` maps (state, event) to one small handler. A pair missing from it
is ignored with no reply, so the table is the whole behaviour.
"""
from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Callable, Optional

import bluetooth_devices as devices_mod

WINDOW_LIMIT_S = 300
HEARTBEAT_TIMEOUT_S = 30

IDLE = "idle"
OPEN = "open"
ADOPTING = "adopting"
CLOSING = "closing"
_ANY = "any"

# Events.
START = "start"
STOP = "stop"
HEARTBEAT = "heartbeat"
TICK = "tick"
DISCOVERED = "discovered"
AGENT_REQUEST = "agent_request"
PAIRED = "paired"
DEVICE_REMOVED = "device_removed"
TAP = "tap"
ADOPT_DONE = "adopt_done"
CLEANUP_DONE = "cleanup_done"
ADAPTER_LOST = "adapter_lost"
FORGET = "forget"
ATTACH = "attach"

# Actions, run by the service in the order given.
ACT_ADAPTER_OPEN = "adapter_open"        # (limit_s,)
ACT_ADAPTER_CLOSE = "adapter_close"
ACT_ADAPTER_ATTACH = "adapter_attach"
ACT_START_DISCOVERY = "start_discovery"
ACT_STOP_DISCOVERY = "stop_discovery"
ACT_SWEEP_BONDS = "sweep_bonds"          # keep only the paired device's bond
ACT_ADOPT = "adopt"                      # (mac, entry step)
ACT_REMOVE_DEVICES = "remove_devices"    # (macs,); fires cleanup_done when done
ACT_SOURCE_ADOPT = "source_adopt"        # (mac,) release the audio hold

ENTRY_PAIR = "pair"
ENTRY_TRUST = "trust"

# Replies.
REPLY_NO_WINDOW = "no_window"
REPLY_UNKNOWN_DEVICE = "unknown_device"
REPLY_CLOSING = "closing"
REPLY_ADOPTING = "adopting"

# Close reasons, kept for the next poll.
REASON_PAIRED = "paired"
REASON_CANCEL = "cancel"
REASON_LIMIT = "limit"
REASON_NO_HEARTBEAT = "no_heartbeat"
REASON_ADAPTER_LOST = "adapter_lost"
REASON_FORGET = "forget"

# A tap on a provisional device only needs trusting (it is bonded already);
# a found device is paired from here first.
_ENTRY_FOR_STATE = {devices_mod.PROVISIONAL: ENTRY_TRUST, devices_mod.FOUND: ENTRY_PAIR}


@dataclass(frozen=True)
class Outcome:
    reply: Optional[str] = None
    actions: tuple = ()


_NOTHING = Outcome()


class WindowMachine:
    """Idle -> Open -> (Adopting) -> Closing -> Idle, plus ``attach`` from
    anywhere. ``paired_mac`` is a getter for the recorded paired device."""

    def __init__(
        self, *, devices: "devices_mod.DeviceList", paired_mac: Callable[[], Optional[str]],
    ) -> None:
        self.devices = devices
        self._paired_mac = paired_mac
        self.state = IDLE
        self.opened_at: Optional[float] = None
        self.last_heartbeat_at: Optional[float] = None
        self.adopting: Optional[str] = None
        self.last_close: Optional[dict] = None
        self.last_error: Optional[str] = None
        # A stop or adapter loss that arrived while a tap's op was running:
        # the op is left to finish, then the window closes for this reason.
        self._close_after_adopt: Optional[str] = None

    # ---- the dispatcher ----

    def handle(self, event: str, now: float, **args) -> Outcome:
        handler = _TABLE.get((self.state, event)) or _TABLE.get((_ANY, event))
        if handler is None:
            return _NOTHING
        return handler(self, now, **args)

    # ---- queries ----

    def is_open(self) -> bool:
        """True only while new pairings are welcome (not during a tap)."""
        return self.state == OPEN

    def is_active(self) -> bool:
        return self.state != IDLE

    def remaining_s(self, now: float) -> Optional[int]:
        if self.state not in (OPEN, ADOPTING) or self.opened_at is None:
            return None
        return max(0, math.ceil(WINDOW_LIMIT_S - (now - self.opened_at)))

    def snapshot(self, now: float) -> dict:
        return {
            "state": self.state,
            "remaining_s": self.remaining_s(now),
            "devices": self.devices.merged(),
            "adopting": self.adopting,
            "last_close": dict(self.last_close) if self.last_close else None,
            "last_error": self.last_error,
        }

    # ---- handlers ----

    def _ignore(self, now: float, **_args) -> Outcome:
        return _NOTHING

    def _no_window(self, now: float, **_args) -> Outcome:
        return Outcome(reply=REPLY_NO_WINDOW)

    def _reply_closing(self, now: float, **_args) -> Outcome:
        return Outcome(reply=REPLY_CLOSING)

    def _reply_adopting(self, now: float, **_args) -> Outcome:
        return Outcome(reply=REPLY_ADOPTING)

    def _open(self, now: float, **_args) -> Outcome:
        self.state = OPEN
        self.opened_at = self.last_heartbeat_at = now
        self.adopting = None
        self.last_close = None
        self.last_error = None
        self._close_after_adopt = None
        self.devices.clear()
        return Outcome(actions=((ACT_ADAPTER_OPEN, WINDOW_LIMIT_S), (ACT_START_DISCOVERY,)))

    def _heartbeat(self, now: float, **_args) -> Outcome:
        self.last_heartbeat_at = now
        return _NOTHING

    def _tick_open(self, now: float, **_args) -> Outcome:
        for expired, reason in _TICK_LIMITS:
            if expired(self, now):
                return self._close(reason)
        return _NOTHING

    def _discovered(self, now: float, mac: str = "", name: str = "", **_args) -> Outcome:
        if mac.upper() != (self._paired_mac() or ""):
            self.devices.on_discovered(mac, name)
        return _NOTHING

    def _agent_request(self, now: float, mac: str = "", passkey: Optional[int] = None,
                       **_args) -> Outcome:
        self.devices.on_agent_accept(mac, passkey)
        return _NOTHING

    def _paired(self, now: float, mac: str = "", **_args) -> Outcome:
        # The paired device re-pairing is a reconnect, and the tapped device's
        # own bond is its op's business; anything else bonded without a tap.
        if mac.upper() not in (self._paired_mac(), self.adopting):
            self.devices.on_paired(mac)
        return _NOTHING

    def _device_removed(self, now: float, mac: str = "", **_args) -> Outcome:
        self.devices.on_gone(mac)
        return _NOTHING

    def _tap(self, now: float, mac: str = "", **_args) -> Outcome:
        mac = mac.upper()
        entry = _ENTRY_FOR_STATE.get(self.devices.state(mac))
        if entry is None:
            return Outcome(reply=REPLY_UNKNOWN_DEVICE)
        self.state = ADOPTING
        self.adopting = mac
        self.last_error = None
        self.devices.on_tap(mac)
        return Outcome(actions=((ACT_ADOPT, mac, entry),))

    def _adopt_done(self, now: float, mac: str = "", ok: bool = False,
                    error: Optional[str] = None, **_args) -> Outcome:
        if mac.upper() != self.adopting:
            return _NOTHING
        if ok:
            self.devices.on_adopted(mac)
            close = self._close(REASON_PAIRED)
            return Outcome(actions=((ACT_SOURCE_ADOPT, mac.upper()),) + close.actions)
        self.devices.on_adopt_failed(mac)
        self.adopting = None
        self.last_error = error or "pairing_failed"
        if self._close_after_adopt is not None:
            return self._close(self._close_after_adopt, error=self.last_error)
        self.state = OPEN
        return _NOTHING

    def _defer_close(self, reason: str) -> Outcome:
        self._close_after_adopt = reason
        return _NOTHING

    def _cleanup_done(self, now: float, **_args) -> Outcome:
        self.state = IDLE
        self.devices.clear()
        return _NOTHING

    def _attach(self, now: float, **_args) -> Outcome:
        # Everything is closed by construction: the adapter is put back at
        # rest and any bond that is not the paired device's is swept.
        self.state = IDLE
        self.adopting = None
        self._close_after_adopt = None
        self.devices.clear()
        return Outcome(actions=((ACT_ADAPTER_ATTACH,), (ACT_SWEEP_BONDS,)))

    def _close(self, reason: str, error: Optional[str] = None) -> Outcome:
        self.state = CLOSING
        self.adopting = None
        self._close_after_adopt = None
        self.last_close = {"reason": reason, "error": error}
        rejected = self.devices.on_window_close()
        return Outcome(actions=(
            (ACT_STOP_DISCOVERY,), (ACT_ADAPTER_CLOSE,), (ACT_REMOVE_DEVICES, rejected),
        ))


def _closer(reason: str):
    return lambda machine, now, **_args: machine._close(reason)


def _deferred_closer(reason: str):
    return lambda machine, now, **_args: machine._defer_close(reason)


# Open's tick: the first limit that has run out closes the window.
_TICK_LIMITS = (
    (lambda m, now: now - m.opened_at >= WINDOW_LIMIT_S, REASON_LIMIT),
    (lambda m, now: now - m.last_heartbeat_at >= HEARTBEAT_TIMEOUT_S, REASON_NO_HEARTBEAT),
)

_TABLE: dict = {
    (IDLE, START): WindowMachine._open,
    (IDLE, HEARTBEAT): WindowMachine._ignore,
    (IDLE, TICK): WindowMachine._ignore,
    (IDLE, TAP): WindowMachine._no_window,
    (IDLE, STOP): WindowMachine._no_window,

    # A second start (another tab, or a retry) attaches to the open window.
    (OPEN, START): WindowMachine._heartbeat,
    (OPEN, HEARTBEAT): WindowMachine._heartbeat,
    (OPEN, TICK): WindowMachine._tick_open,
    (OPEN, DISCOVERED): WindowMachine._discovered,
    (OPEN, AGENT_REQUEST): WindowMachine._agent_request,
    (OPEN, PAIRED): WindowMachine._paired,
    (OPEN, DEVICE_REMOVED): WindowMachine._device_removed,
    (OPEN, TAP): WindowMachine._tap,
    (OPEN, STOP): _closer(REASON_CANCEL),
    (OPEN, ADAPTER_LOST): _closer(REASON_ADAPTER_LOST),
    (OPEN, FORGET): _closer(REASON_FORGET),

    # During a tap the limits wait for the op (it has its own cap); the
    # agent only accepts the tapped device, so its requests need nothing.
    (ADOPTING, START): WindowMachine._heartbeat,
    (ADOPTING, HEARTBEAT): WindowMachine._heartbeat,
    (ADOPTING, TICK): WindowMachine._ignore,
    (ADOPTING, AGENT_REQUEST): WindowMachine._ignore,
    (ADOPTING, DISCOVERED): WindowMachine._discovered,
    (ADOPTING, PAIRED): WindowMachine._paired,
    (ADOPTING, DEVICE_REMOVED): WindowMachine._device_removed,
    (ADOPTING, TAP): WindowMachine._reply_adopting,
    (ADOPTING, ADOPT_DONE): WindowMachine._adopt_done,
    (ADOPTING, STOP): _deferred_closer(REASON_CANCEL),
    (ADOPTING, ADAPTER_LOST): _deferred_closer(REASON_ADAPTER_LOST),
    (ADOPTING, FORGET): _closer(REASON_FORGET),

    (CLOSING, START): WindowMachine._reply_closing,
    (CLOSING, TAP): WindowMachine._no_window,
    (CLOSING, CLEANUP_DONE): WindowMachine._cleanup_done,

    (_ANY, ATTACH): WindowMachine._attach,
}
