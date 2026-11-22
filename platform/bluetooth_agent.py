#!/usr/bin/python3
"""bluetooth_agent.py

Copyright (c) 2026 Lo-tech Systems Limited. All rights reserved.

The BlueZ org.bluez.Agent1 pairing agent for the autostream_bluetooth daemon.

The agent registers as ``DisplayYesNo``. With ``NoInputNoOutput`` bluetoothd
accepts an incoming Just Works pairing by itself without asking the agent,
so nothing could hold such a device back; as DisplayYesNo the agent is
consulted for every pairing. A phone pairs by numeric comparison against it:
the code is accepted at once and shown in the pairing list, and the user's
tap on the entry is the consent.

The accept/refuse decision (``PairingPolicy``) is the security-relevant
logic here and is kept pure and independent of dbus so that it is directly
unit-testable: two predicates over injected getters, one table naming which
predicate and side effect each agent method gets, and one injected side
effect, ``mark_provisional(mac, passkey)``. The dbus service object itself
(``build_agent_class``) is constructed lazily via a factory function, since
``dbus.service.Object`` can only be subclassed once python3-dbus is known to
be importable.
"""
from __future__ import annotations

import logging
from typing import Callable, Optional

from bluetooth_bluez import _mac_from_path  # noqa: F401 (re-exported convenience)

logger = logging.getLogger(__name__)

AGENT_PATH = "/lo_tech/autostream/bluetooth/agent"
AGENT_INTERFACE = "org.bluez.Agent1"
AGENT_CAPABILITY = "DisplayYesNo"

REJECT_ERROR = "org.bluez.Error.Rejected"

# The request kinds the policy decides on, one per agent method that asks.
KIND_AUTHORIZE = "authorize"                  # RequestAuthorization
KIND_CONFIRM = "confirm"                      # RequestConfirmation
KIND_AUTHORIZE_SERVICE = "authorize_service"  # AuthorizeService
KIND_PIN_CODE = "pin_code"                    # RequestPinCode
KIND_PASSKEY = "passkey"                      # RequestPasskey
KIND_DISPLAY_PASSKEY = "display_passkey"      # DisplayPasskey
KIND_DISPLAY_PIN_CODE = "display_pin_code"    # DisplayPinCode


def _uuid16(short: str) -> str:
    return f"0000{short}-0000-1000-8000-00805f9b34fb"


# Services a source may ask for on an audio link: A2DP, Audio Source and
# Sink, the AVRCP family, and AVDTP. Nothing else has a server on this box.
AUDIO_UUIDS = frozenset(_uuid16(u) for u in (
    "110d", "110a", "110b", "110c", "110e", "110f", "0019",
))

# Hands-free and headset services: refused, named in the log so a phone that
# asks for them is easy to recognise.
_VOICE_UUIDS = frozenset(_uuid16(u) for u in ("111e", "1108", "111f"))


class PairingPolicy:
    """Pure decision core for the pairing agent.

    Getters: ``window_open()`` (new pairings welcome), ``adopting()`` (the
    device a tap is pairing, or None), ``paired_mac()`` (the recorded paired
    device), ``provisional_macs()`` (bonded devices awaiting a tap). Side
    effect: ``mark_provisional(mac, passkey)``, called for an accepted
    pairing from any device that is neither the tapped one nor the paired
    one, once per accepted request.
    """

    def __init__(
        self,
        *,
        window_open: Callable[[], bool],
        adopting: Callable[[], Optional[str]],
        paired_mac: Callable[[], Optional[str]],
        provisional_macs: Callable[[], frozenset],
        mark_provisional: Callable[[str, Optional[int]], None],
    ) -> None:
        self._window_open = window_open
        self._adopting = adopting
        self._paired_mac = paired_mac
        self._provisional_macs = provisional_macs
        self._mark_provisional = mark_provisional

    # ---- predicates ----

    def _pairing_allowed(self, mac: str, uuid: Optional[str]) -> bool:
        # The tapped device may complete its own pairing while the window is
        # busy with it; anything else only while the window is open.
        return bool(self._window_open()) or (mac != "" and mac == _upper(self._adopting()))

    def _service_allowed(self, mac: str, uuid: Optional[str]) -> bool:
        known = {_upper(self._paired_mac()), _upper(self._adopting())}
        known |= {_upper(m) for m in self._provisional_macs()}
        return (uuid or "").lower() in AUDIO_UUIDS and mac in known - {None}

    def _never(self, mac: str, uuid: Optional[str]) -> bool:
        return False

    # ---- side effects ----

    def _mark(self, mac: str, passkey: Optional[int]) -> None:
        if mac not in (_upper(self._adopting()), _upper(self._paired_mac())):
            self._mark_provisional(mac, passkey)

    # ---- the decision ----

    def decide(
        self, request_kind: str, device_mac: str, *,
        passkey: Optional[int] = None, uuid: Optional[str] = None,
    ) -> bool:
        mac = _upper(device_mac) or ""
        predicate, side_effect = _RULES.get(request_kind, _REFUSE)
        decision = predicate(self, mac, uuid)
        if decision and side_effect is not None:
            side_effect(self, mac, passkey)
        detail = ""
        if uuid:
            detail = " (hands-free/headset)" if uuid.lower() in _VOICE_UUIDS else f" ({uuid})"
        logger.info(
            "Bluetooth agent %s for %s%s: %s",
            request_kind, mac, detail, "accepted" if decision else "rejected",
        )
        return decision


# Agent method kind -> (predicate, side effect on accept). PIN kinds are
# never appropriate: an audio source pairs by Just Works or numeric
# comparison, and a peer asking to display a passkey is a keyboard.
_REFUSE = (PairingPolicy._never, None)
_RULES = {
    KIND_AUTHORIZE: (PairingPolicy._pairing_allowed, PairingPolicy._mark),
    KIND_CONFIRM: (PairingPolicy._pairing_allowed, PairingPolicy._mark),
    KIND_AUTHORIZE_SERVICE: (PairingPolicy._service_allowed, None),
    KIND_PIN_CODE: _REFUSE,
    KIND_PASSKEY: _REFUSE,
    KIND_DISPLAY_PASSKEY: _REFUSE,
    KIND_DISPLAY_PIN_CODE: _REFUSE,
}


def _upper(mac: Optional[str]) -> Optional[str]:
    return mac.upper() if mac else None


def build_agent_class(dbus):
    """Return the org.bluez.Agent1 dbus.service.Object subclass.

    Constructed lazily -- called only once dbus is known importable (from
    bluetooth_service.py at daemon startup) -- so this module stays importable
    without python3-dbus present. Every method delegates the decision to a
    ``PairingPolicy`` instance and raises ``org.bluez.Error.Rejected`` on a
    refusal.
    """
    import dbus.service

    def _decide(policy: PairingPolicy, kind: str, device, **extra) -> None:
        mac = _mac_from_path(str(device)) or ""
        if not policy.decide(kind, mac, **extra):
            raise dbus.exceptions.DBusException(REJECT_ERROR, "not authorised")

    class Agent(dbus.service.Object):
        def __init__(self, bus, path: str, policy: PairingPolicy) -> None:
            super().__init__(bus, path)
            self._policy = policy

        @dbus.service.method(AGENT_INTERFACE, in_signature="", out_signature="")
        def Release(self) -> None:
            logger.info("Bluetooth pairing agent released")

        @dbus.service.method(AGENT_INTERFACE, in_signature="o", out_signature="s")
        def RequestPinCode(self, device) -> str:
            _decide(self._policy, KIND_PIN_CODE, device)
            return ""

        @dbus.service.method(AGENT_INTERFACE, in_signature="os", out_signature="")
        def DisplayPinCode(self, device, pincode) -> None:
            _decide(self._policy, KIND_DISPLAY_PIN_CODE, device)

        @dbus.service.method(AGENT_INTERFACE, in_signature="o", out_signature="u")
        def RequestPasskey(self, device):
            _decide(self._policy, KIND_PASSKEY, device)
            return dbus.UInt32(0)

        @dbus.service.method(AGENT_INTERFACE, in_signature="ouq", out_signature="")
        def DisplayPasskey(self, device, passkey, entered) -> None:
            _decide(self._policy, KIND_DISPLAY_PASSKEY, device)

        @dbus.service.method(AGENT_INTERFACE, in_signature="ou", out_signature="")
        def RequestConfirmation(self, device, passkey) -> None:
            _decide(self._policy, KIND_CONFIRM, device, passkey=int(passkey))

        @dbus.service.method(AGENT_INTERFACE, in_signature="o", out_signature="")
        def RequestAuthorization(self, device) -> None:
            _decide(self._policy, KIND_AUTHORIZE, device)

        @dbus.service.method(AGENT_INTERFACE, in_signature="os", out_signature="")
        def AuthorizeService(self, device, uuid) -> None:
            _decide(self._policy, KIND_AUTHORIZE_SERVICE, device, uuid=str(uuid))

        @dbus.service.method(AGENT_INTERFACE, in_signature="", out_signature="")
        def Cancel(self) -> None:
            # A provisional entry stays listed: the bond may still complete.
            logger.info("Bluetooth pairing agent: request cancelled by peer")

    return Agent
