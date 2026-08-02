#!/usr/bin/python3
"""bluetooth_commands.py

Copyright (c) 2026 Lo-tech Systems Limited. All rights reserved.

Multi-step BlueZ device operations, driven entirely on the GLib loop thread
via ``bluetooth_bluez.BluezClient``'s async (reply_handler=/error_handler=)
device calls. One small class per chain, with a named method per step rather
than nested closures, so a traceback (or a debugger) names an actual method
instead of ``<lambda>`` three deep.

Each op takes an ``is_stale`` predicate supplied by the caller: polled before
every step and before the final report, it lets the service abandon an op
whose outcome no longer matters (the pairing window closed, or a newer op
has since started for a different target) without that stale result landing
late and being misattributed. This mirrors the state machine's own
``mac != pairing_target_mac`` guard in ``on_pair_result`` -- the difference
is that an op checks *before* doing further D-Bus work, rather than doing
the work and discarding the answer afterwards.
"""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Callable, Optional

if TYPE_CHECKING:
    import bluetooth_bluez as bluez_mod

logger = logging.getLogger(__name__)


class PairAndTrustOp:
    """Pair -> trust -> connect -> remove the previously-paired device (if
    different) -> report, matching ``BluetoothStateMachine.on_pair_result``'s
    signature: ``on_result(mac, success, error)``.

    Pairs (and trusts, connects) the new device *before* touching the old
    one: if any of those three steps fails, the previously-trusted device
    must remain paired/trusted rather than being stranded with BlueZ no
    longer bonding it -- so the old-device removal is the last step, run
    only once the new device is fully up. A failure removing the old device
    is logged and swallowed rather than failing the op: the new device is
    already paired, trusted, and connected by that point, so it is usable
    regardless of whether the old bond was cleaned up. A Connect() failure,
    by contrast, *does* fail the op (reported through *on_result*), matching
    the pairing worker this replaces, where a raised connect_device() failed
    the pairing outright.
    """

    def __init__(
        self,
        client: "bluez_mod.BluezClient",
        mac: str,
        old_mac: Optional[str],
        on_result: Callable[[str, bool, Optional[str]], None],
        is_stale: Callable[[], bool],
    ) -> None:
        self._client = client
        self._mac = mac
        self._old_mac = old_mac
        self._on_result = on_result
        self._is_stale = is_stale

    def start(self) -> None:
        if self._is_stale():
            return
        self._client.pair_async(self._mac, self._on_paired, self._on_pair_error)

    def _on_paired(self) -> None:
        if self._is_stale():
            return
        self._client.set_trusted_async(self._mac, True, self._on_trusted, self._on_trust_error)

    def _on_pair_error(self, error: Exception) -> None:
        if self._is_stale():
            return
        self._on_result(self._mac, False, str(error))

    def _on_trusted(self) -> None:
        if self._is_stale():
            return
        self._client.connect_async(self._mac, self._on_connected, self._on_connect_error)

    def _on_trust_error(self, error: Exception) -> None:
        if self._is_stale():
            return
        self._on_result(self._mac, False, str(error))

    def _on_connected(self) -> None:
        if self._is_stale():
            return
        if self._old_mac and self._old_mac != self._mac:
            self._client.remove_device_async(
                self._old_mac, self._on_old_removed, self._on_old_remove_error
            )
        else:
            self._report_success()

    def _on_connect_error(self, error: Exception) -> None:
        if self._is_stale():
            return
        self._on_result(self._mac, False, str(error))

    def _on_old_removed(self) -> None:
        self._report_success()

    def _on_old_remove_error(self, error: Exception) -> None:
        logger.warning(
            "Failed to remove replaced device %s after pairing %s: %s",
            self._old_mac, self._mac, error,
        )
        self._report_success()

    def _report_success(self) -> None:
        if self._is_stale():
            return
        self._on_result(self._mac, True, None)


class ReconnectProbeOp:
    """is-connected probe -> Connect() if not already connected, mirroring
    ``reconnect_tick()``'s worker semantics exactly: a probe failure is
    logged and falls through to attempting Connect() anyway rather than
    aborting, and a Connect() failure (including a routine
    ``org.bluez.Error.InProgress`` -- a connect attempt already under way)
    is logged and swallowed, never reported as a failure.

    *on_result* is called with ``(mac, True)`` only for the "already
    connected" probe outcome -- matching
    ``BluetoothStateMachine.on_link_state_changed``'s signature -- since the
    worker being replaced never proactively reported a Connect() it issued
    itself either; that arrives (or doesn't) via the ordinary
    PropertiesChanged subscription.
    """

    def __init__(
        self,
        client: "bluez_mod.BluezClient",
        mac: str,
        on_result: Callable[[str, bool], None],
        is_stale: Callable[[], bool],
    ) -> None:
        self._client = client
        self._mac = mac
        self._on_result = on_result
        self._is_stale = is_stale

    def start(self) -> None:
        if self._is_stale():
            return
        self._client.is_connected_async(self._mac, self._on_probe_result, self._on_probe_error)

    def _on_probe_result(self, connected: bool) -> None:
        if self._is_stale():
            return
        if connected:
            self._on_result(self._mac, True)
            return
        self._client.connect_async(self._mac, self._on_connected, self._on_connect_error)

    def _on_probe_error(self, error: Exception) -> None:
        logger.info("Reconnect supervisor: is_connected check failed for %s: %s", self._mac, error)
        if self._is_stale():
            return
        self._client.connect_async(self._mac, self._on_connected, self._on_connect_error)

    def _on_connected(self) -> None:
        # No proactive report on a Connect() this op issued itself -- see
        # class docstring; the PropertiesChanged subscription is the path
        # that tells the state machine a link came up.
        pass

    def _on_connect_error(self, error: Exception) -> None:
        logger.info("Reconnect attempt to %s failed: %s", self._mac, error)
