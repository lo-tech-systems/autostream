#!/usr/bin/python3
"""bluetooth_devices.py

Copyright (c) 2026 Lo-tech Systems Limited. All rights reserved.

The pairing window's device list for the autostream_bluetooth daemon: one
entry per MAC that was found by discovery or that asked to pair in, each
with its own small lifecycle. Pure: no D-Bus, no timers, no window limits.
The window machine (``bluetooth_window.py``) feeds it events and asks it
which devices must be removed when the window closes.

Lifecycle of one entry (``_TRANSITIONS`` is the whole of it):

  Found        a discovery result
  Provisional  an incoming pairing the agent accepted, or a bond that
               appeared without the agent; bonded but untrusted, unrecorded
               and silent
  Confirming   the user tapped it and the adoption op is running
  Paired       adopted: it is now the paired device
  Rejected     provisional when the window closed or another device was
               adopted; its bond is removed by the window's clean-up
  Gone         no longer known (the entry is dropped from the list)

``audio_mac()`` is the hold: it answers the paired MAC and nothing else, so
a provisional or confirming device is never the audio source and the paired
device keeps playing until the user taps the new one.
"""
from __future__ import annotations

import itertools
from dataclasses import dataclass
from typing import Callable, Optional

FOUND = "found"
PROVISIONAL = "provisional"
CONFIRMING = "confirming"
PAIRED = "paired"
REJECTED = "rejected"
GONE = "gone"

SOURCE_SCAN = "scan"
SOURCE_INCOMING = "incoming"

# Events.
DISCOVERED = "discovered"
AGENT_ACCEPT = "agent_accept"
PAIRED_SIGNAL = "paired_signal"
TAP = "tap"
ADOPT_OK = "adopt_ok"
ADOPT_FAILED = "adopt_failed"
WINDOW_CLOSE = "window_close"
OTHER_ADOPTED = "other_adopted"
INTERFACES_REMOVED = "interfaces_removed"
FORGET = "forget"

# Next state after an adoption fails: back to where the entry came from, so
# the user may tap it again.
_RETRY_STATE = {SOURCE_INCOMING: PROVISIONAL, SOURCE_SCAN: FOUND}

# (current state, event) -> next state. ``None`` as the current state means
# "no entry for this MAC yet". A pair missing from the table is ignored: the
# entry keeps its state. ``_RETRY`` is resolved from the entry's source.
_RETRY = "retry"
_ANY = "any"
_TRANSITIONS: dict = {
    (None, DISCOVERED): FOUND,
    (None, AGENT_ACCEPT): PROVISIONAL,
    (None, PAIRED_SIGNAL): PROVISIONAL,
    (FOUND, DISCOVERED): FOUND,
    (FOUND, AGENT_ACCEPT): PROVISIONAL,
    (FOUND, PAIRED_SIGNAL): PROVISIONAL,
    (FOUND, TAP): CONFIRMING,
    (FOUND, WINDOW_CLOSE): GONE,
    (PROVISIONAL, DISCOVERED): PROVISIONAL,
    (PROVISIONAL, AGENT_ACCEPT): PROVISIONAL,
    (PROVISIONAL, PAIRED_SIGNAL): PROVISIONAL,
    (PROVISIONAL, TAP): CONFIRMING,
    (PROVISIONAL, WINDOW_CLOSE): REJECTED,
    (PROVISIONAL, OTHER_ADOPTED): REJECTED,
    (CONFIRMING, ADOPT_OK): PAIRED,
    (CONFIRMING, ADOPT_FAILED): _RETRY,
    # A window closed under a running tap (forget, or a daemon stopping)
    # leaves a bond nobody confirmed; it goes with the provisional ones.
    (CONFIRMING, WINDOW_CLOSE): REJECTED,
    (PAIRED, FORGET): GONE,
    (_ANY, INTERFACES_REMOVED): GONE,
}

# Entries the merged list shows; rejected ones are on their way out.
_LISTED_STATES = frozenset({FOUND, PROVISIONAL, CONFIRMING, PAIRED})


@dataclass
class DeviceEntry:
    mac: str
    name: str
    source: str
    passkey: Optional[int]
    state: str
    since: int


class DeviceList:
    """The merged list of found and incoming devices for one window.

    ``paired_mac`` is a getter for the daemon's recorded paired device; the
    list never stores it, so there is one source of truth for the hold.
    """

    def __init__(self, *, paired_mac: Callable[[], Optional[str]]) -> None:
        self._paired_mac = paired_mac
        self._entries: dict[str, DeviceEntry] = {}
        self._order = itertools.count()

    # ---- events ----

    def on_discovered(self, mac: str, name: str = "") -> None:
        self._apply(mac, DISCOVERED, name=name, source=SOURCE_SCAN)

    def on_agent_accept(self, mac: str, passkey: Optional[int] = None) -> None:
        self._apply(mac, AGENT_ACCEPT, passkey=passkey, source=SOURCE_INCOMING)

    def on_paired(self, mac: str) -> None:
        self._apply(mac, PAIRED_SIGNAL, source=SOURCE_INCOMING)

    def on_tap(self, mac: str) -> None:
        self._apply(mac, TAP)

    def on_adopted(self, mac: str) -> None:
        """The tapped device is now the paired device; every other
        provisional device is rejected so the same clean-up removes it."""
        self._apply(mac, ADOPT_OK)
        for other in list(self._entries):
            if other != mac.upper():
                self._apply(other, OTHER_ADOPTED)

    def on_adopt_failed(self, mac: str) -> None:
        self._apply(mac, ADOPT_FAILED)

    def on_gone(self, mac: str) -> None:
        self._apply(mac, INTERFACES_REMOVED)

    def on_forget(self, mac: str) -> None:
        self._apply(mac, FORGET)

    def on_window_close(self) -> tuple:
        """Apply ``window_close`` to every entry and return the MACs whose
        bonds the clean-up must remove (``rejected_after_close``)."""
        for mac in list(self._entries):
            self._apply(mac, WINDOW_CLOSE)
        return self.rejected_after_close()

    def set_name(self, mac: str, name: str) -> None:
        """Record a name learnt after the entry was made (an Alias lookup or
        a property change). Not a lifecycle event."""
        entry = self._entries.get((mac or "").upper())
        if entry is not None and name:
            entry.name = str(name)

    def clear(self) -> None:
        self._entries.clear()

    # ---- queries ----

    def state(self, mac: str) -> Optional[str]:
        entry = self._entries.get((mac or "").upper())
        return entry.state if entry is not None else None

    def provisional_macs(self) -> frozenset:
        return frozenset(m for m, e in self._entries.items() if e.state == PROVISIONAL)

    def rejected_after_close(self) -> tuple:
        return tuple(e.mac for e in self._sorted() if e.state == REJECTED)

    def name(self, mac: str) -> str:
        """The entry's display name (falls back to the MAC)."""
        entry = self._entries.get((mac or "").upper())
        if entry is None:
            return (mac or "").upper()
        return entry.name or entry.mac

    def audio_mac(self) -> Optional[str]:
        return self._paired_mac()

    def merged(self) -> list:
        """The list for status: ``[{mac, name, source, state, passkey}]`` in
        the order entries first appeared."""
        return [
            {"mac": e.mac, "name": e.name or e.mac, "source": e.source,
             "state": e.state, "passkey": e.passkey}
            for e in self._sorted() if e.state in _LISTED_STATES
        ]

    # ---- the dispatcher ----

    def _sorted(self) -> list:
        return sorted(self._entries.values(), key=lambda e: e.since)

    def _apply(
        self, mac: str, event: str, *, name: str = "", passkey: Optional[int] = None,
        source: str = SOURCE_SCAN,
    ) -> None:
        mac = (mac or "").upper()
        if not mac:
            return
        entry = self._entries.get(mac)
        current = entry.state if entry is not None else None
        nxt = _TRANSITIONS.get((current, event)) or _TRANSITIONS.get((_ANY, event))
        if nxt is None or (entry is None and nxt == GONE):
            return
        if nxt == GONE:
            del self._entries[mac]
            return
        if entry is None:
            entry = DeviceEntry(mac=mac, name="", source=source, passkey=None,
                                state=nxt, since=next(self._order))
            self._entries[mac] = entry
        if nxt == _RETRY:
            nxt = _RETRY_STATE[entry.source]
        if nxt == PROVISIONAL:
            # A scanned device that then pairs in holds a bond now, so a
            # failed tap returns it to Provisional rather than Found.
            entry.source = SOURCE_INCOMING
        if passkey is not None:
            # A retried comparison shows its latest code.
            entry.passkey = passkey
        if name:
            entry.name = str(name)
        entry.state = nxt
