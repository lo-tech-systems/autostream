#!/usr/bin/python3
"""bluetooth_commands.py

Copyright (c) 2026 Lo-tech Systems Limited. All rights reserved.

Multi-step BlueZ device operations, driven entirely on the GLib loop thread
via ``bluetooth_bluez.BluezClient``'s async (reply_handler=/error_handler=)
device calls. One small class per chain, with a named method per step rather
than nested closures, so a traceback (or a debugger) names an actual method
instead of ``<lambda>`` three deep.

The adopt op takes an ``is_stale`` predicate supplied by the
caller: polled before every step and before the final report, it lets the
service abandon an op whose outcome no longer matters (the window closed
under it, or the device was forgotten) without that stale result landing
late and being misattributed. This mirrors the state machine's own
``mac != adopting`` guard in ``on_adopt_result`` -- the difference is that
an op checks *before* doing further D-Bus work, rather than doing the work
and discarding the answer afterwards.
"""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Callable, Optional

from bluetooth_window import ENTRY_PAIR, ENTRY_TRUST  # noqa: F401 (entry steps)

if TYPE_CHECKING:
    import bluetooth_bluez as bluez_mod

logger = logging.getLogger(__name__)


class AdoptDeviceOp:
    """Adopt the device the user tapped: [pair ->] trust -> [connect ->]
    remove the previously-paired device (if different) -> report, as
    ``on_result(mac, success, error)``.

    ``entry`` picks where the chain starts. ``"pair"`` is a device found by
    scanning: it is paired, trusted and connected from here. ``"trust"`` is
    a device that already paired in by itself: it holds a bond and connects
    in on its own, so it only needs trusting.

    The new device is brought up *before* the old one is touched: if any of
    its steps fails, the previously-trusted device must remain paired and
    trusted rather than being stranded with BlueZ no longer bonding it -- so
    the old-device removal is the last step, run only once the new device is
    fully up. A failure removing the old device is logged and swallowed
    rather than failing the op: the new device is already usable by then. A
    Connect() failure, by contrast, *does* fail a ``"pair"`` op.
    """

    def __init__(
        self,
        client: "bluez_mod.BluezClient",
        mac: str,
        entry: str,
        old_mac: Optional[str],
        on_result: Callable[[str, bool, Optional[str]], None],
        is_stale: Callable[[], bool],
    ) -> None:
        self._client = client
        self._mac = mac
        self._entry = entry
        self._old_mac = old_mac
        self._on_result = on_result
        self._is_stale = is_stale

    def start(self) -> None:
        if self._is_stale():
            return
        if self._entry == ENTRY_TRUST:
            self._trust()
        else:
            self._client.pair_async(self._mac, self._on_paired, self._on_step_error)

    def _on_paired(self) -> None:
        if self._is_stale():
            return
        self._trust()

    def _trust(self) -> None:
        self._client.set_trusted_async(self._mac, True, self._on_trusted, self._on_step_error)

    def _on_trusted(self) -> None:
        if self._is_stale():
            return
        if self._entry == ENTRY_TRUST:
            self._remove_old()
        else:
            self._client.connect_async(self._mac, self._on_connected, self._on_step_error)

    def _on_connected(self) -> None:
        if self._is_stale():
            return
        self._remove_old()

    def _on_step_error(self, error: Exception) -> None:
        if self._is_stale():
            return
        self._on_result(self._mac, False, str(error))

    def _remove_old(self) -> None:
        if self._old_mac and self._old_mac != self._mac:
            self._client.remove_device_async(
                self._old_mac, self._on_old_removed, self._on_old_remove_error
            )
        else:
            self._report_success()

    def _on_old_removed(self) -> None:
        self._report_success()

    def _on_old_remove_error(self, error: Exception) -> None:
        logger.warning(
            "Failed to remove replaced device %s after adopting %s: %s",
            self._old_mac, self._mac, error,
        )
        self._report_success()

    def _report_success(self) -> None:
        if self._is_stale():
            return
        self._on_result(self._mac, True, None)


class RemoveDevicesOp:
    """Disconnect then remove each of a set of devices, one after another,
    then call ``on_done()`` once. Used when a pairing window closes, for the
    provisional devices nobody tapped.

    Tolerant throughout: a device that has already gone, or was never
    connected, is the goal state, so a failed Disconnect() still goes on to
    RemoveDevice(), and a failed RemoveDevice() is logged and the next device
    is taken. ``on_done`` always fires, so the window can always finish
    closing.
    """

    def __init__(
        self,
        client: "bluez_mod.BluezClient",
        macs,
        on_done: Callable[[], None],
    ) -> None:
        self._client = client
        self._pending = list(macs)
        self._on_done = on_done
        self._current: Optional[str] = None

    def start(self) -> None:
        self._next()

    def _next(self) -> None:
        if not self._pending:
            self._on_done()
            return
        self._current = self._pending.pop(0)
        try:
            self._client.disconnect_async(self._current, self._remove, self._on_disconnect_error)
        except Exception as e:
            self._on_disconnect_error(e)

    def _on_disconnect_error(self, error: Exception) -> None:
        logger.debug("Disconnect of %s before removal failed: %s", self._current, error)
        self._remove()

    def _remove(self) -> None:
        try:
            self._client.remove_device_async(self._current, self._on_removed, self._on_remove_error)
        except Exception as e:
            self._on_remove_error(e)

    def _on_removed(self) -> None:
        logger.info("Removed unconfirmed device %s", self._current)
        self._next()

    def _on_remove_error(self, error: Exception) -> None:
        logger.warning("Failed to remove unconfirmed device %s: %s", self._current, error)
        self._next()

