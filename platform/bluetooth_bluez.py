#!/usr/bin/python3
"""bluetooth_bluez.py

Copyright (c) 2026 Lo-tech Systems Limited. All rights reserved.

The one place that talks to BlueZ over D-Bus for the autostream_bluetooth
daemon, mirroring wifi_nm.py's "one module invokes the external stack"
convention: every method that reaches BlueZ is
bounded by an explicit D-Bus call timeout, so there is no unbounded D-Bus
code path.

``python3-dbus`` is imported lazily (inside ``BluezClient.connect()``, not at
module import time) because dev machines and the WSL test runner do not have
it installed. The pure helpers at module level (MAC validation, scan-result
filtering/parsing, device-path <-> MAC translation) have no dbus dependency
at all and are unit-testable directly.
"""
from __future__ import annotations

import logging
import os
import re
from typing import Callable, Optional

logger = logging.getLogger(__name__)

BLUEZ_SERVICE = "org.bluez"
ADAPTER_IFACE = "org.bluez.Adapter1"
DEVICE_IFACE = "org.bluez.Device1"
MEDIA_TRANSPORT_IFACE = "org.bluez.MediaTransport1"
OBJECT_MANAGER_IFACE = "org.freedesktop.DBus.ObjectManager"
PROPERTIES_IFACE = "org.freedesktop.DBus.Properties"

# Every D-Bus call is bounded (family convention, cf. wifi_nm.NMClient).
DEFAULT_CALL_TIMEOUT = 10.0      # adapter/property/discovery calls
DEFAULT_PAIR_TIMEOUT = 30.0      # Device1.Pair() — matches the pairing-window timeout
DEFAULT_CONNECT_TIMEOUT = 15.0   # Device1.Connect() / Disconnect()

MAC_RE = re.compile(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")


def is_valid_mac(mac: str) -> bool:
    """True when *mac* is a well-formed AA:BB:CC:DD:EE:FF address string."""
    return bool(MAC_RE.match(mac or ""))


def mac_to_object_suffix(mac: str) -> str:
    """AA:BB:CC:DD:EE:FF -> dev_AA_BB_CC_DD_EE_FF (BlueZ's device object naming)."""
    return "dev_" + mac.upper().replace(":", "_")


def _mac_from_path(path: str) -> Optional[str]:
    """Recover AA:BB:CC:DD:EE:FF from a .../dev_AA_BB_CC_DD_EE_FF object path.

    Returns None when *path* does not look like a BlueZ device object path.
    """
    if not path:
        return None
    tail = path.rsplit("/", 1)[-1]
    if not tail.startswith("dev_"):
        return None
    parts = tail[len("dev_"):].split("_")
    if len(parts) != 6:
        return None
    mac = ":".join(parts).upper()
    return mac if is_valid_mac(mac) else None


# UUIDs signalling the remote device can act as an audio SOURCE. We are the
# A2DP *sink*; a compatible turntable advertises AudioSource (0x110A) and/or
# the generic Advanced Audio Distribution service class (0x110D). Matched
# case-insensitively against Device1.UUIDs.
_AUDIO_SOURCE_UUID = "0000110a-0000-1000-8000-00805f9b34fb"
_ADVANCED_AUDIO_UUID = "0000110d-0000-1000-8000-00805f9b34fb"
AUDIO_CAPABLE_UUIDS = frozenset({_AUDIO_SOURCE_UUID, _ADVANCED_AUDIO_UUID})

# The Bluetooth Class of Device "major device class" field occupies bits
# 8-12 of the 24-bit value; 0x04 is "Audio/Video".
_MAJOR_CLASS_MASK = 0x1F00
_AUDIO_VIDEO_MAJOR_CLASS = 0x0400


def is_audio_capable_device(props: dict) -> bool:
    """True when a scanned device's UUIDs/Class indicate an audio source.

    Pure function over BlueZ Device1 properties (as delivered by
    InterfacesAdded/GetManagedObjects), so it is unit-testable without a
    D-Bus connection. Used to filter scan results to audio sources.
    """
    uuids = props.get("UUIDs") or []
    for u in uuids:
        if str(u).lower() in AUDIO_CAPABLE_UUIDS:
            return True
    klass = props.get("Class")
    if isinstance(klass, int) and (klass & _MAJOR_CLASS_MASK) == _AUDIO_VIDEO_MAJOR_CLASS:
        return True
    return False


def transport_sample_rate(props: dict) -> Optional[int]:
    """Best-effort A2DP sample rate from a MediaTransport1 property set
    (pragmatic rate negotiation).

    BlueZ's MediaTransport1 does not expose a plain sample-rate property —
    only a codec ID and a codec-specific ``Configuration`` byte blob that
    would need full A2DP SBC/AAC bit-layout decoding to interpret reliably.
    That decoding is deliberately out of scope as overkill for this use case:
    this reads whatever the transport object reports under a plain numeric
    property (``Rate``/``SampleRate`` — present on some BlueZ/BlueALSA
    configurations) and returns ``None`` when it isn't determinable, so the
    caller (the pump) falls back to its own default/negotiated rate.
    """
    for key in ("Rate", "SampleRate"):
        rate = props.get(key)
        if isinstance(rate, (int, float)) and not isinstance(rate, bool) and rate > 0:
            return int(rate)
    return None


def parse_device_props(path: str, props: dict) -> dict:
    """Translate BlueZ Device1 properties (+ object path) into the plain dict
    shape used throughout this daemon: {mac, name, rssi, paired, audio_capable}.
    """
    mac = props.get("Address") or _mac_from_path(path) or ""
    name = props.get("Alias") or props.get("Name") or ""
    rssi = props.get("RSSI")
    return {
        "mac": str(mac).upper(),
        "name": str(name),
        "rssi": int(rssi) if isinstance(rssi, (int, float)) and not isinstance(rssi, bool) else None,
        "paired": bool(props.get("Paired", False)),
        "audio_capable": is_audio_capable_device(props),
    }


# ---------------------------------------------------------------------------
# Adapter bus classification: when both a USB
# adapter and the onboard radio are present, prefer the USB one. Pure/
# injectable helpers so the preference logic is testable without a D-Bus
# connection or a real /sys tree.
# ---------------------------------------------------------------------------

ADAPTER_KIND_USB = "usb"
ADAPTER_KIND_ONBOARD = "onboard"
ADAPTER_KIND_UNKNOWN = "unknown"


def _default_sysfs_device_realpath(hci_name: str) -> Optional[str]:
    """Resolve ``/sys/class/bluetooth/<hci_name>/device`` (a symlink into the
    bus subtree, e.g. .../usb3/3-1/... for a USB dongle, .../platform/...
    for an onboard radio). Returns ``None`` when the path does not exist
    (adapter already gone, or a non-Linux/test environment)."""
    path = f"/sys/class/bluetooth/{hci_name}/device"
    if not os.path.exists(path):
        return None
    try:
        return os.path.realpath(path)
    except OSError:
        return None


def adapter_kind_for_path(
    adapter_path: str, sysfs_reader: Optional[Callable[[str], Optional[str]]] = None
) -> str:
    """Classify a BlueZ adapter object path (e.g. ``/org/bluez/hci0``) as
    ``"usb"``, ``"onboard"``, or ``"unknown"``, by resolving its sysfs device
    symlink. *sysfs_reader* is injectable for tests; defaults to reading the
    real ``/sys/class/bluetooth`` tree."""
    hci_name = adapter_path.rsplit("/", 1)[-1]
    reader = sysfs_reader or _default_sysfs_device_realpath
    try:
        resolved = reader(hci_name)
    except Exception:
        return ADAPTER_KIND_UNKNOWN
    if not resolved:
        return ADAPTER_KIND_UNKNOWN
    return ADAPTER_KIND_USB if "usb" in resolved.lower() else ADAPTER_KIND_ONBOARD


def choose_adapter_path(
    adapter_paths: list, sysfs_reader: Optional[Callable[[str], Optional[str]]] = None
) -> Optional[str]:
    """Pick which of *adapter_paths* to use: a USB adapter over an onboard
    one when both are present, else whichever (single adapter, or none)."""
    if not adapter_paths:
        return None
    for path in adapter_paths:
        if adapter_kind_for_path(path, sysfs_reader) == ADAPTER_KIND_USB:
            return path
    return adapter_paths[0]


class BluezUnavailable(RuntimeError):
    """Raised when python3-dbus / python3-gi are not importable, or no
    BlueZ adapter can be found."""


def _import_dbus():
    try:
        import dbus  # noqa: F401
        import dbus.mainloop.glib  # noqa: F401
        import dbus.service  # noqa: F401
        import dbus.exceptions  # noqa: F401
    except ImportError as e:
        raise BluezUnavailable(f"python3-dbus is required: {e}") from e
    return dbus


def _plain(value):
    """Recursively convert dbus-python boxed types to plain Python values.

    dbus.Array/Dictionary/String/Boolean/Int32/... all subclass their plain
    Python equivalents, but json.dumps and equality-heavy test assertions are
    friendlier against the unboxed forms, and callers of this module should
    never need to import dbus themselves to interpret a callback payload.
    """
    if isinstance(value, dict):
        return {str(k): _plain(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_plain(v) for v in value]
    if isinstance(value, bool):
        return bool(value)
    if isinstance(value, int):
        return int(value)
    if isinstance(value, float):
        return float(value)
    return str(value) if not isinstance(value, (str, type(None))) else value


class BluezClient:
    """All BlueZ D-Bus interaction for the autostream_bluetooth daemon.

    Every method is bounded by an explicit timeout. dbus is imported lazily
    on first use (``connect()``) so this module stays importable — and its
    pure helpers testable — on systems without the D-Bus stack.

    ``connect()`` must be called after ``dbus.mainloop.glib.DBusGMainLoop``
    has been installed as the default main loop (bluetooth_service.py does
    this before constructing the client) so signal callbacks are delivered
    on the GLib loop the service runs.
    """

    def __init__(
        self,
        call_timeout: float = DEFAULT_CALL_TIMEOUT,
        sysfs_reader: Optional[Callable[[str], Optional[str]]] = None,
    ) -> None:
        self._call_timeout = call_timeout
        self._sysfs_reader = sysfs_reader
        self._dbus = None
        self._bus = None
        self._adapter_path: Optional[str] = None
        self._adapter_kind: Optional[str] = None

        self._on_device_found: Optional[Callable[[dict], None]] = None
        self._on_props_changed: Optional[Callable[[str, dict], None]] = None
        self._on_transport_changed: Optional[Callable[[bool, Optional[int]], None]] = None

    # ---- setup ----

    def connect(self) -> None:
        dbus = _import_dbus()
        self._dbus = dbus
        self._bus = dbus.SystemBus()
        self._adapter_path = self._find_adapter_path()
        if self._adapter_path is None:
            raise BluezUnavailable("No BlueZ adapter found")
        logger.info(
            "Using BlueZ adapter at %s (kind=%s)", self._adapter_path, self._adapter_kind
        )

    @property
    def adapter_present(self) -> bool:
        return self._adapter_path is not None

    @property
    def adapter_kind(self) -> Optional[str]:
        """``"usb"`` / ``"onboard"`` / ``"unknown"``, or ``None`` before an
        adapter has been found."""
        return self._adapter_kind

    def _object_manager(self):
        return self._dbus.Interface(
            self._bus.get_object(BLUEZ_SERVICE, "/"), OBJECT_MANAGER_IFACE
        )

    def _find_adapter_path(self) -> Optional[str]:
        objects = self._object_manager().GetManagedObjects(
            dbus_interface=OBJECT_MANAGER_IFACE, timeout=self._call_timeout
        )
        adapter_paths = [str(path) for path, ifaces in objects.items() if ADAPTER_IFACE in ifaces]
        chosen = choose_adapter_path(adapter_paths, self._sysfs_reader)
        self._adapter_kind = adapter_kind_for_path(chosen, self._sysfs_reader) if chosen else None
        return chosen

    def _device_path(self, mac: str) -> str:
        return f"{self._adapter_path}/{mac_to_object_suffix(mac)}"

    def _props_iface(self, path: str):
        return self._dbus.Interface(
            self._bus.get_object(BLUEZ_SERVICE, path), PROPERTIES_IFACE
        )

    # ---- adapter control ----

    def power_on(self) -> None:
        self._props_iface(self._adapter_path).Set(
            ADAPTER_IFACE, "Powered", True, timeout=self._call_timeout
        )

    def set_pairable(self, pairable: bool) -> None:
        """Set Pairable on/off. PairableTimeout is left at 0 (no BlueZ-side
        timeout) — the pairing window is timed by the service's own state
        machine, which calls this to close the window too."""
        props = self._props_iface(self._adapter_path)
        props.Set(ADAPTER_IFACE, "PairableTimeout", self._dbus.UInt32(0),
                   timeout=self._call_timeout)
        props.Set(ADAPTER_IFACE, "Pairable", bool(pairable), timeout=self._call_timeout)

    def ensure_not_discoverable(self) -> None:
        """We are never discoverable — the sink is found by us discovering
        the turntable, not the other way around."""
        self._props_iface(self._adapter_path).Set(
            ADAPTER_IFACE, "Discoverable", False, timeout=self._call_timeout
        )

    def _adapter_iface(self):
        return self._dbus.Interface(
            self._bus.get_object(BLUEZ_SERVICE, self._adapter_path), ADAPTER_IFACE
        )

    def start_discovery(self) -> None:
        try:
            self._adapter_iface().StartDiscovery(timeout=self._call_timeout)
        except self._dbus.exceptions.DBusException as e:
            if "InProgress" not in str(e):
                raise

    def stop_discovery(self) -> None:
        try:
            self._adapter_iface().StopDiscovery(timeout=self._call_timeout)
        except self._dbus.exceptions.DBusException as e:
            if "Failed" not in str(e) and "NotReady" not in str(e):
                raise

    # ---- device ops ----

    def _device_iface(self, mac: str):
        return self._dbus.Interface(
            self._bus.get_object(BLUEZ_SERVICE, self._device_path(mac)), DEVICE_IFACE
        )

    def pair(self, mac: str, timeout: float = DEFAULT_PAIR_TIMEOUT) -> None:
        self._device_iface(mac).Pair(timeout=timeout)

    def connect_device(self, mac: str, timeout: float = DEFAULT_CONNECT_TIMEOUT) -> None:
        self._device_iface(mac).Connect(timeout=timeout)

    def disconnect_device(self, mac: str, timeout: float = DEFAULT_CONNECT_TIMEOUT) -> None:
        self._device_iface(mac).Disconnect(timeout=timeout)

    def remove_device(self, mac: str) -> None:
        """Idempotent: a device that is already absent is the goal state."""
        try:
            self._adapter_iface().RemoveDevice(
                self._device_path(mac), timeout=self._call_timeout
            )
        except self._dbus.exceptions.DBusException as e:
            if "DoesNotExist" not in str(e).replace(" ", ""):
                raise

    def remove_cached_devices(self, keep_macs) -> int:
        """Remove every cached, non-paired Device1 object BlueZ already
        knows about, except those in *keep_macs*. Returns the count removed.

        BlueZ only emits InterfacesAdded for a device object it has never
        seen before; anything already cached from an earlier discovery
        session sits there silently on later scans, with no signal ever
        firing for it again. Calling this immediately before StartDiscovery
        clears that cache so every nearby device re-arrives through the
        normal InterfacesAdded path.

        One bounded GetManagedObjects enumeration finds the candidates;
        each RemoveDevice call is independently bounded, and a per-device
        failure is logged and skipped rather than aborting the purge.
        """
        keep = {str(m).upper() for m in (keep_macs or ())}
        objects = self._object_manager().GetManagedObjects(
            dbus_interface=OBJECT_MANAGER_IFACE, timeout=self._call_timeout
        )
        removed = 0
        for path, ifaces in objects.items():
            if DEVICE_IFACE not in ifaces:
                continue
            props = ifaces[DEVICE_IFACE]
            mac = str(props.get("Address") or _mac_from_path(str(path)) or "").upper()
            if mac and mac in keep:
                continue
            if bool(props.get("Paired", False)):
                continue
            try:
                self._adapter_iface().RemoveDevice(str(path), timeout=self._call_timeout)
                removed += 1
            except self._dbus.exceptions.DBusException as e:
                logger.debug("remove_cached_devices: failed to remove %s: %s", path, e)
        return removed

    def set_trusted(self, mac: str, trusted: bool = True) -> None:
        self._props_iface(self._device_path(mac)).Set(
            DEVICE_IFACE, "Trusted", bool(trusted), timeout=self._call_timeout
        )

    def is_connected(self, mac: str) -> bool:
        """Bounded Device1.Connected getter: used by the
        reconnect supervisor to avoid hammering Connect() against a device
        BlueZ already reports connected, and by the pair-success hook to pick
        up a Connected=True that arrived mid-pairing, before the device was
        trusted, and so was never attributed to anyone by
        ``_on_props_changed``. A device that no longer exists is reported as
        not-connected rather than raising.
        """
        try:
            return bool(self._props_iface(self._device_path(mac)).Get(
                DEVICE_IFACE, "Connected", timeout=self._call_timeout
            ))
        except self._dbus.exceptions.DBusException as e:
            if "DoesNotExist" in str(e).replace(" ", ""):
                return False
            raise

    def find_existing_state(self) -> dict:
        """Snapshot already-existing BlueZ device/transport objects.

        Used at startup and on adapter (re)attach: a daemon
        restart while a stream is active never gets a fresh
        InterfacesAdded/PropertiesChanged for the device or MediaTransport1
        object that are already there — BlueZ only signals on *change* — so
        without this the service would be stuck reporting "disconnected"
        and zero-filling forever after a restart. Returns
        ``{"devices": {MAC: connected_bool}, "transport_active": bool,
        "transport_rate": Optional[int]}``.
        """
        objects = self._object_manager().GetManagedObjects(
            dbus_interface=OBJECT_MANAGER_IFACE, timeout=self._call_timeout
        )
        devices: dict = {}
        transport_active = False
        transport_rate = None
        for path, ifaces in objects.items():
            if DEVICE_IFACE in ifaces:
                props = _plain(ifaces[DEVICE_IFACE])
                mac = props.get("Address") or _mac_from_path(str(path)) or ""
                if mac:
                    devices[str(mac).upper()] = bool(props.get("Connected", False))
            if MEDIA_TRANSPORT_IFACE in ifaces:
                transport_active = True
                transport_rate = transport_sample_rate(_plain(ifaces[MEDIA_TRANSPORT_IFACE]))
        return {
            "devices": devices,
            "transport_active": transport_active,
            "transport_rate": transport_rate,
        }

    # ---- signals ----

    def subscribe(
        self,
        on_device_found: Callable[[dict], None],
        on_props_changed: Callable[[str, dict], None],
        on_transport_changed: Callable[[bool, Optional[int]], None],
    ) -> None:
        """Register InterfacesAdded/InterfacesRemoved/PropertiesChanged
        handlers feeding the state machine.

        ``on_device_found(device_dict)`` fires for newly discovered Device1
        objects (scan results, already filtered to audio-capable devices);
        ``on_props_changed(mac, changed_props)`` fires for Device1 property
        changes (link state); ``on_transport_changed(active, rate)`` fires
        when a MediaTransport1 object appears/disappears (A2DP stream
        start/stop) — driving the pump, never polled. ``rate`` is the
        transport's negotiated sample rate when determinable (see
        ``transport_sample_rate()``), else ``None`` on both appear and
        disappear.
        """
        self._on_device_found = on_device_found
        self._on_props_changed = on_props_changed
        self._on_transport_changed = on_transport_changed

        self._bus.add_signal_receiver(
            self._handle_interfaces_added,
            dbus_interface=OBJECT_MANAGER_IFACE,
            signal_name="InterfacesAdded",
        )
        self._bus.add_signal_receiver(
            self._handle_interfaces_removed,
            dbus_interface=OBJECT_MANAGER_IFACE,
            signal_name="InterfacesRemoved",
        )
        self._bus.add_signal_receiver(
            self._handle_props_changed,
            dbus_interface=PROPERTIES_IFACE,
            signal_name="PropertiesChanged",
            path_keyword="path",
        )

    def _handle_interfaces_added(self, path, interfaces) -> None:
        path = str(path)
        if DEVICE_IFACE in interfaces and self._on_device_found:
            props = _plain(interfaces[DEVICE_IFACE])
            device = parse_device_props(path, props)
            if device["audio_capable"]:
                self._on_device_found(device)
        if MEDIA_TRANSPORT_IFACE in interfaces and self._on_transport_changed:
            rate = transport_sample_rate(_plain(interfaces[MEDIA_TRANSPORT_IFACE]))
            self._on_transport_changed(True, rate)

    def _handle_interfaces_removed(self, path, interfaces) -> None:
        if MEDIA_TRANSPORT_IFACE in interfaces and self._on_transport_changed:
            self._on_transport_changed(False, None)

    def _handle_props_changed(self, interface, changed, invalidated, path=None) -> None:
        if interface != DEVICE_IFACE or not self._on_props_changed:
            return
        mac = _mac_from_path(str(path)) or ""
        self._on_props_changed(mac, _plain(changed))
