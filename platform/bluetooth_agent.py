#!/usr/bin/python3
"""bluetooth_agent.py

Copyright (c) 2026 Lo-tech Systems Limited. All rights reserved.

The BlueZ org.bluez.Agent1 pairing agent for the autostream_bluetooth daemon,
capability NoInputNoOutput (Just-Works — BT turntables have no display/keypad).

The accept/reject decision (``should_accept`` / ``PairingPolicy``) is the
security-relevant logic here and is kept pure and independent of dbus so
that it is directly unit-testable. The dbus
service object itself (``build_agent_class``) is constructed lazily via a
factory function, since ``dbus.service.Object`` can only be subclassed once
python3-dbus is known to be importable.
"""
from __future__ import annotations

import logging
from typing import Callable, Optional

from bluetooth_bluez import _mac_from_path  # noqa: F401 (re-exported convenience)

logger = logging.getLogger(__name__)

AGENT_PATH = "/lo_tech/autostream/bluetooth/agent"
AGENT_INTERFACE = "org.bluez.Agent1"
AGENT_CAPABILITY = "NoInputNoOutput"

REJECT_ERROR = "org.bluez.Error.Rejected"

# The three request kinds the policy decides on.
KIND_CONFIRM = "confirm"                # RequestConfirmation
KIND_AUTHORIZE = "authorize"            # RequestAuthorization
KIND_AUTHORIZE_SERVICE = "authorize_service"  # AuthorizeService


def should_accept(
    request_kind: str,
    *,
    pairing_window_open: bool,
    pairing_target_mac: Optional[str],
    device_mac: str,
    trusted_mac: Optional[str],
) -> bool:
    """Pure accept/reject decision for one agent callback.

    RequestConfirmation/RequestAuthorization: accept only when a pairing
    window is open AND the requesting MAC is the in-flight pairing target.

    AuthorizeService: accept when the MAC is the in-flight pairing target
    (during the pairing window) OR is the already-trusted paired device
    (routine service authorisation on reconnect). Everything else is
    rejected — including every request when nothing is paired/pairing.
    """
    device_mac = (device_mac or "").upper()
    target = pairing_target_mac.upper() if pairing_target_mac else None
    trusted = trusted_mac.upper() if trusted_mac else None

    is_pairing_target = bool(pairing_window_open) and target is not None and device_mac == target

    if request_kind in (KIND_CONFIRM, KIND_AUTHORIZE):
        return is_pairing_target
    if request_kind == KIND_AUTHORIZE_SERVICE:
        return is_pairing_target or (trusted is not None and device_mac == trusted)
    return False


class PairingPolicy:
    """Pure decision core for the pairing agent, closing over the live
    pairing-window/target/trusted state via injected callables so this class
    carries no D-Bus dependency and can be unit-tested directly.
    """

    def __init__(
        self,
        *,
        pairing_window_open: Callable[[], bool],
        pairing_target_mac: Callable[[], Optional[str]],
        trusted_mac: Callable[[], Optional[str]],
    ) -> None:
        self._pairing_window_open = pairing_window_open
        self._pairing_target_mac = pairing_target_mac
        self._trusted_mac = trusted_mac

    def decide(self, request_kind: str, device_mac: str) -> bool:
        decision = should_accept(
            request_kind,
            pairing_window_open=self._pairing_window_open(),
            pairing_target_mac=self._pairing_target_mac(),
            device_mac=device_mac,
            trusted_mac=self._trusted_mac(),
        )
        logger.info(
            "Bluetooth agent %s for %s: %s",
            request_kind, device_mac, "accepted" if decision else "rejected",
        )
        return decision


def build_agent_class(dbus):
    """Return the org.bluez.Agent1 dbus.service.Object subclass.

    Constructed lazily — called only once dbus is known importable (from
    bluetooth_service.py at daemon startup) — so this module stays importable
    without python3-dbus present. Every method delegates the decision to a
    ``PairingPolicy`` instance and raises ``org.bluez.Error.Rejected`` on a
    reject, matching ``should_accept``'s policy exactly.
    """
    import dbus.service

    class Agent(dbus.service.Object):
        def __init__(self, bus, path: str, policy: PairingPolicy) -> None:
            super().__init__(bus, path)
            self._policy = policy

        @dbus.service.method(AGENT_INTERFACE, in_signature="", out_signature="")
        def Release(self) -> None:
            logger.info("Bluetooth pairing agent released")

        @dbus.service.method(AGENT_INTERFACE, in_signature="o", out_signature="s")
        def RequestPinCode(self, device) -> str:
            # NoInputNoOutput: PIN entry is never appropriate; always reject.
            raise dbus.exceptions.DBusException(
                REJECT_ERROR, "PIN entry not supported (NoInputNoOutput)"
            )

        @dbus.service.method(AGENT_INTERFACE, in_signature="os", out_signature="")
        def DisplayPinCode(self, device, pincode) -> None:
            raise dbus.exceptions.DBusException(
                REJECT_ERROR, "no display available (NoInputNoOutput)"
            )

        @dbus.service.method(AGENT_INTERFACE, in_signature="o", out_signature="u")
        def RequestPasskey(self, device):
            raise dbus.exceptions.DBusException(
                REJECT_ERROR, "passkey entry not supported (NoInputNoOutput)"
            )

        @dbus.service.method(AGENT_INTERFACE, in_signature="ouq", out_signature="")
        def DisplayPasskey(self, device, passkey, entered) -> None:
            raise dbus.exceptions.DBusException(
                REJECT_ERROR, "no display available (NoInputNoOutput)"
            )

        @dbus.service.method(AGENT_INTERFACE, in_signature="ou", out_signature="")
        def RequestConfirmation(self, device, passkey) -> None:
            mac = _mac_from_path(str(device)) or ""
            if not self._policy.decide(KIND_CONFIRM, mac):
                raise dbus.exceptions.DBusException(REJECT_ERROR, "not authorised")

        @dbus.service.method(AGENT_INTERFACE, in_signature="o", out_signature="")
        def RequestAuthorization(self, device) -> None:
            mac = _mac_from_path(str(device)) or ""
            if not self._policy.decide(KIND_AUTHORIZE, mac):
                raise dbus.exceptions.DBusException(REJECT_ERROR, "not authorised")

        @dbus.service.method(AGENT_INTERFACE, in_signature="os", out_signature="")
        def AuthorizeService(self, device, uuid) -> None:
            mac = _mac_from_path(str(device)) or ""
            if not self._policy.decide(KIND_AUTHORIZE_SERVICE, mac):
                raise dbus.exceptions.DBusException(REJECT_ERROR, "not authorised")

        @dbus.service.method(AGENT_INTERFACE, in_signature="", out_signature="")
        def Cancel(self) -> None:
            logger.info("Bluetooth pairing agent: request cancelled by peer")

    return Agent
