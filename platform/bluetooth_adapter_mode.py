#!/usr/bin/python3
"""bluetooth_adapter_mode.py

Copyright (c) 2026 Lo-tech Systems Limited. All rights reserved.

The adapter's discoverable/pairable/connectable mode for the
autostream_bluetooth daemon, as three idempotent write sequences:

  at_attach()          the resting mode, set whenever an adapter is attached
  open_window(limit)   discoverable and pairable for one pairing window
  close_window()       back to rest

Each sequence is a table of (property, value) writes made in order through
one injected writer (``BluezClient.set_adapter_property`` in the daemon), so
this module has no D-Bus dependency. Every write is attempted on its own
and a failure never raises: the adapter may have gone (a dongle pulled
mid-window) and the remaining writes are still worth trying.

Connectable is asserted after every Discoverable=false: under the kernel's
connection control, clearing discoverable can clear connectable too, and a
bonded source must still be able to reconnect while the appliance rests.

The device class is not written here. It is persisted in bluetoothd's own
configuration (Audio/Video, Loudspeaker), so a source searching for a sink
sees the right kind of device and there is nothing to restore per window.
"""
from __future__ import annotations

import logging
from typing import Callable

logger = logging.getLogger(__name__)

# The kernel and bluetoothd timeouts set when a window opens run this much
# longer than the window, so they close discoverable and pairable by
# themselves only when the daemon is no longer there to do it.
BACKSTOP_SLACK_S = 10


class AdapterMode:
    def __init__(
        self, *, write: Callable[[str, object], None], hostname: Callable[[], str],
    ) -> None:
        self._write = write
        self._hostname = hostname

    def at_attach(self) -> bool:
        return self._apply("attach", (
            ("Alias", self._hostname()),
            ("Discoverable", False),
            ("Pairable", False),
            ("Connectable", True),
        ))

    def open_window(self, limit_s: int) -> bool:
        backstop = int(limit_s) + BACKSTOP_SLACK_S
        # The timeouts go first: a flag set before its timeout would run
        # with whatever timeout was left from before.
        return self._apply("open", (
            ("PairableTimeout", backstop),
            ("Pairable", True),
            ("DiscoverableTimeout", backstop),
            ("Discoverable", True),
            ("Connectable", True),
        ))

    def close_window(self) -> bool:
        return self._apply("close", (
            ("Discoverable", False),
            ("Pairable", False),
            ("Connectable", True),
        ))

    def _apply(self, label: str, writes: tuple) -> bool:
        failed = []
        for name, value in writes:
            try:
                self._write(name, value)
            except Exception as e:
                failed.append(f"{name} ({e})")
        if failed:
            logger.debug("bluetooth adapter mode %s: not set: %s", label, "; ".join(failed))
        return not failed
