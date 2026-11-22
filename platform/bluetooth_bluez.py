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
DEFAULT_PAIR_TIMEOUT = 30.0      # Device1.Pair() — the cap on a tapped device's pairing
DEFAULT_CONNECT_TIMEOUT = 15.0   # Device1.Connect() / Disconnect()

MAC_RE = re.compile(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")


def is_valid_mac(mac: str) -> bool:
    """True when *mac* is a well-formed AA:BB:CC:DD:EE:FF address string."""
    return bool(MAC_RE.match(mac or ""))


def mac_to_object_suffix(mac: str) -> str:
    """AA:BB:CC:DD:EE:FF -> dev_AA_BB_CC_DD_EE_FF (BlueZ's device object naming)."""
    return "dev_" + mac.upper().replace(":", "_")


def _mac_in_path(path: str) -> Optional[str]:
    """The device MAC named anywhere in a BlueZ object path: the device
    itself (.../dev_AA_..._FF) or an object under it, such as a media
    transport (.../dev_AA_..._FF/sep1/fd0). None when there is none."""
    for part in (path or "").split("/"):
        if part.startswith("dev_"):
            return _mac_from_path(part)
    return None


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

    Reads whatever the transport object reports under a plain numeric
    property (``Rate``/``SampleRate`` — present on some BlueZ/BlueALSA
    configurations) and returns ``None`` when it isn't determinable. Callers
    should prefer the decoded ``Configuration`` blob (see
    ``transport_codec_and_rate``) and treat this as the fallback.
    """
    for key in ("Rate", "SampleRate"):
        rate = props.get(key)
        if isinstance(rate, (int, float)) and not isinstance(rate, bool) and rate > 0:
            return int(rate)
    return None


# A2DP codec ID, per the Bluetooth Assigned Numbers "Media Codec Type"
# table used in MediaTransport1's ``Codec`` property. Vendor-specific codecs
# (aptX etc.) all share 0xFF and are not decoded further by this stack.
_CODEC_NAMES = {0x00: "SBC", 0x01: "MPEG-1/2", 0x02: "AAC", 0xFF: "Vendor"}

# SBC codec-specific-information-elements, octet 0: upper nibble = sampling
# frequency, lower nibble = channel mode (A2DP spec, single bit set for a
# negotiated Configuration rather than a Capabilities bitmask).
_SBC_SAMPLE_RATE_HZ = {0b1000: 16000, 0b0100: 32000, 0b0010: 44100, 0b0001: 48000}
_SBC_CHANNEL_MODES = {0b1000: "mono", 0b0100: "dual", 0b0010: "stereo", 0b0001: "joint_stereo"}


def decode_transport_codec(codec_byte, configuration_bytes) -> dict:
    """Decode an A2DP ``Codec`` id + ``Configuration`` blob into
    ``{"codec": str, "sample_rate": int | None, "channel_mode": str | None}``.

    Pure, dbus-free, and never raises: a missing/short/malformed
    *configuration_bytes* (any indexable sequence of ints, or ``None``)
    yields ``sample_rate``/``channel_mode`` of ``None`` rather than an
    exception. Only SBC's Configuration layout is decoded; other codecs
    report their name with ``sample_rate``/``channel_mode`` left ``None``.
    """
    try:
        codec_int = int(codec_byte)
    except (TypeError, ValueError):
        codec_int = None

    if codec_int is None:
        codec_name = "Unknown"
    else:
        codec_name = _CODEC_NAMES.get(codec_int) or f"Unknown (0x{codec_int:02X})"

    sample_rate = None
    channel_mode = None
    if codec_int == 0x00:  # SBC
        try:
            first_byte = int(configuration_bytes[0])
        except (TypeError, IndexError, ValueError, KeyError):
            first_byte = None
        if first_byte is not None:
            sample_rate = _SBC_SAMPLE_RATE_HZ.get((first_byte >> 4) & 0x0F)
            channel_mode = _SBC_CHANNEL_MODES.get(first_byte & 0x0F)

    return {"codec": codec_name, "sample_rate": sample_rate, "channel_mode": channel_mode}


def transport_codec_and_rate(props: dict) -> dict:
    """Best-effort codec name + sample rate for a MediaTransport1 property
    set, combining the decoded ``Configuration`` blob with the plain
    ``Rate``/``SampleRate`` fallback.

    Returns ``{"codec": str | None, "sample_rate": int | None}``. Rate
    precedence: decoded ``Configuration`` > plain ``Rate``/``SampleRate``
    property > ``None``. ``codec`` is ``None`` only when the transport
    exposes no ``Codec`` property at all.
    """
    codec_byte = props.get("Codec")
    codec_name = None
    sample_rate = None
    if codec_byte is not None:
        decoded = decode_transport_codec(codec_byte, props.get("Configuration") or ())
        codec_name = decoded["codec"]
        sample_rate = decoded["sample_rate"]
    if sample_rate is None:
        sample_rate = transport_sample_rate(props)
    return {"codec": codec_name, "sample_rate": sample_rate}


# MediaTransport1.State -> what it means for the audio source. "pending" is
# a stream starting that BlueALSA is about to acquire.
TRANSPORT_ACTIVE = "active"
TRANSPORT_IDLE = "idle"
TRANSPORT_REMOVED = "removed"
_TRANSPORT_STATES = {"active": TRANSPORT_ACTIVE, "pending": TRANSPORT_ACTIVE, "idle": TRANSPORT_IDLE}

# Adapter1 properties the daemon writes, with the D-Bus type each needs.
_ADAPTER_PROPERTY_TYPES = {
    "Alias": "string",
    "Discoverable": "bool",
    "Pairable": "bool",
    "Connectable": "bool",
    "DiscoverableTimeout": "uint32",
    "PairableTimeout": "uint32",
}


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
        self._on_transport: Optional[Callable[..., None]] = None
        self._on_device_removed: Optional[Callable[[str], None]] = None
        self._on_adapter_lost: Optional[Callable[[], None]] = None

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

    def set_adapter_property(self, name: str, value) -> None:
        """Write one Adapter1 property, boxed as the type BlueZ expects.
        Which properties are written, and when, is
        ``bluetooth_adapter_mode``'s business; this only carries the write."""
        if self._adapter_path is None:
            raise BluezUnavailable("No BlueZ adapter attached")
        boxers = {
            "string": self._dbus.String,
            "bool": self._dbus.Boolean,
            "uint32": self._dbus.UInt32,
        }
        boxed = boxers[_ADAPTER_PROPERTY_TYPES[name]](value)
        self._props_iface(self._adapter_path).Set(
            ADAPTER_IFACE, name, boxed, timeout=self._call_timeout
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

    # ---- async device ops (loop-thread only) ----
    #
    # dbus-python's reply_handler=/error_handler= form: the call returns
    # immediately, and the matching handler is invoked once the reply (or a
    # D-Bus error/timeout) arrives on the GLib main loop these must be issued
    # from. Every one of these still carries an explicit timeout -- the
    # method call itself is non-blocking, but the *reply* is not guaranteed
    # otherwise, and an unbounded op would defeat the point of moving off a
    # worker thread.

    def pair_async(
        self,
        mac: str,
        on_success: Callable[[], None],
        on_error: Callable[[Exception], None],
        timeout: float = DEFAULT_PAIR_TIMEOUT,
    ) -> None:
        """Async Device1.Pair(). *on_success* takes no arguments (Pair()
        has no return value); *on_error* takes the raised exception."""
        self._device_iface(mac).Pair(
            reply_handler=lambda: on_success(),
            error_handler=on_error,
            timeout=timeout,
        )

    def connect_async(
        self,
        mac: str,
        on_success: Callable[[], None],
        on_error: Callable[[Exception], None],
        timeout: float = DEFAULT_CONNECT_TIMEOUT,
    ) -> None:
        self._device_iface(mac).Connect(
            reply_handler=lambda: on_success(),
            error_handler=on_error,
            timeout=timeout,
        )

    def disconnect_async(
        self,
        mac: str,
        on_success: Callable[[], None],
        on_error: Callable[[Exception], None],
        timeout: float = DEFAULT_CONNECT_TIMEOUT,
    ) -> None:
        self._device_iface(mac).Disconnect(
            reply_handler=lambda: on_success(),
            error_handler=on_error,
            timeout=timeout,
        )

    def set_trusted_async(
        self,
        mac: str,
        trusted: bool,
        on_success: Callable[[], None],
        on_error: Callable[[Exception], None],
        timeout: float = DEFAULT_CALL_TIMEOUT,
    ) -> None:
        self._props_iface(self._device_path(mac)).Set(
            DEVICE_IFACE, "Trusted", bool(trusted),
            reply_handler=lambda: on_success(),
            error_handler=on_error,
            timeout=timeout,
        )

    def remove_device_async(
        self,
        mac: str,
        on_success: Callable[[], None],
        on_error: Callable[[Exception], None],
        timeout: float = DEFAULT_CALL_TIMEOUT,
    ) -> None:
        """Async RemoveDevice(), idempotent like remove_device(): a
        DoesNotExist error (device already gone) is reported through
        *on_success*, not *on_error* -- an absent device is the goal state
        either way."""
        def _on_error(e: Exception) -> None:
            if "DoesNotExist" in str(e).replace(" ", ""):
                on_success()
            else:
                on_error(e)

        self._adapter_iface().RemoveDevice(
            self._device_path(mac),
            reply_handler=lambda: on_success(),
            error_handler=_on_error,
            timeout=timeout,
        )

    def is_connected_async(
        self,
        mac: str,
        on_result: Callable[[bool], None],
        on_error: Callable[[Exception], None],
        timeout: float = DEFAULT_CALL_TIMEOUT,
    ) -> None:
        """Async Device1.Connected getter (see is_connected() for why callers
        want this). A DoesNotExist error is reported as not-connected through
        *on_result*, mirroring the synchronous form, rather than through
        *on_error*."""
        def _on_reply(value) -> None:
            on_result(bool(value))

        def _on_error(e: Exception) -> None:
            if "DoesNotExist" in str(e).replace(" ", ""):
                on_result(False)
            else:
                on_error(e)

        self._props_iface(self._device_path(mac)).Get(
            DEVICE_IFACE, "Connected",
            reply_handler=_on_reply,
            error_handler=_on_error,
            timeout=timeout,
        )

    def device_alias_async(
        self,
        mac: str,
        on_result: Callable[[str], None],
        on_error: Callable[[Exception], None],
        timeout: float = DEFAULT_CALL_TIMEOUT,
    ) -> None:
        """Async Device1.Alias getter (the device's own name, or its address
        when it has none), for a device that paired in before its name was
        known."""
        self._props_iface(self._device_path(mac)).Get(
            DEVICE_IFACE, "Alias",
            reply_handler=lambda value: on_result(str(value)),
            error_handler=on_error,
            timeout=timeout,
        )

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
        return self._remove_devices(keep_macs, bonded=False)

    def remove_bonded_devices(self, keep_macs) -> int:
        """Remove every bonded (Paired) Device1 except those in
        *keep_macs*. Returns the count removed. Run at attach so a bond
        left by a pairing window the daemon did not live to close (a
        device nobody tapped) never outlives it."""
        return self._remove_devices(keep_macs, bonded=True)

    def _remove_devices(self, keep_macs, *, bonded: bool) -> int:
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
            if bool(props.get("Paired", False)) != bonded:
                continue
            try:
                self._adapter_iface().RemoveDevice(str(path), timeout=self._call_timeout)
                removed += 1
            except self._dbus.exceptions.DBusException as e:
                logger.debug("remove devices: failed to remove %s: %s", path, e)
        return removed

    def set_trusted(self, mac: str, trusted: bool = True) -> None:
        self._props_iface(self._device_path(mac)).Set(
            DEVICE_IFACE, "Trusted", bool(trusted), timeout=self._call_timeout
        )

    def is_connected(self, mac: str) -> bool:
        """Bounded Device1.Connected getter: used by the pair-success hook to pick
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
        ``{"devices": {MAC: connected_bool}, "transports": [{"path", "mac",
        "rate", "codec"}]}``.
        """
        objects = self._object_manager().GetManagedObjects(
            dbus_interface=OBJECT_MANAGER_IFACE, timeout=self._call_timeout
        )
        devices: dict = {}
        transports: list = []
        for path, ifaces in objects.items():
            if DEVICE_IFACE in ifaces:
                props = _plain(ifaces[DEVICE_IFACE])
                mac = props.get("Address") or _mac_from_path(str(path)) or ""
                if mac:
                    devices[str(mac).upper()] = bool(props.get("Connected", False))
            if MEDIA_TRANSPORT_IFACE in ifaces:
                transports.append(self._transport_entry(str(path), _plain(ifaces[MEDIA_TRANSPORT_IFACE])))
        return {"devices": devices, "transports": transports}

    @staticmethod
    def _transport_entry(path: str, props: dict) -> dict:
        info = transport_codec_and_rate(props)
        mac = _mac_in_path(str(props.get("Device") or "")) or _mac_in_path(path)
        return {"path": path, "mac": mac, "rate": info["sample_rate"], "codec": info["codec"]}

    # ---- signals ----

    def subscribe(
        self,
        *,
        on_device_found: Callable[[dict], None],
        on_props_changed: Callable[[str, dict], None],
        on_transport: Callable[..., None],
        on_device_removed: Callable[[str], None],
        on_adapter_lost: Callable[[], None],
    ) -> None:
        """Register InterfacesAdded/InterfacesRemoved/PropertiesChanged
        handlers feeding the state machine. Call once: the receivers live on
        the shared system bus connection and survive an adapter re-attach.

        ``on_device_found(device_dict)`` fires for newly discovered Device1
        objects (already filtered to audio-capable devices);
        ``on_props_changed(mac, changed_props)`` for Device1 property
        changes (link state, a bond completing, a name learnt);
        ``on_transport(path, mac, state, rate, codec)`` whenever a
        MediaTransport1 object appears (``state`` "active", as a new stream
        has always been treated), changes State ("active" or "idle"), or
        disappears ("removed") -- driving the pump, never polled. ``rate``/
        ``codec`` are the negotiated values when known (see
        ``transport_codec_and_rate()``), else ``None``.
        ``on_device_removed(mac)`` fires when BlueZ drops a Device1 object,
        and ``on_adapter_lost()`` when the attached adapter disappears (a
        dongle pulled), after which ``adapter_present`` is False.
        """
        self._on_device_found = on_device_found
        self._on_props_changed = on_props_changed
        self._on_transport = on_transport
        self._on_device_removed = on_device_removed
        self._on_adapter_lost = on_adapter_lost

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
        if MEDIA_TRANSPORT_IFACE in interfaces and self._on_transport:
            entry = self._transport_entry(path, _plain(interfaces[MEDIA_TRANSPORT_IFACE]))
            self._on_transport(path, entry["mac"], TRANSPORT_ACTIVE, entry["rate"], entry["codec"])

    def _handle_interfaces_removed(self, path, interfaces) -> None:
        path = str(path)
        if MEDIA_TRANSPORT_IFACE in interfaces and self._on_transport:
            self._on_transport(path, _mac_in_path(path), TRANSPORT_REMOVED, None, None)
        if DEVICE_IFACE in interfaces and self._on_device_removed:
            mac = _mac_from_path(path)
            if mac:
                self._on_device_removed(mac)
        if ADAPTER_IFACE in interfaces and path == self._adapter_path:
            logger.warning("BlueZ adapter %s removed", path)
            self._adapter_path = None
            if self._on_adapter_lost:
                self._on_adapter_lost()

    def _handle_props_changed(self, interface, changed, invalidated, path=None) -> None:
        path = str(path)
        if interface == DEVICE_IFACE and self._on_props_changed:
            self._on_props_changed(_mac_from_path(path) or "", _plain(changed))
        elif interface == MEDIA_TRANSPORT_IFACE and self._on_transport and "State" in changed:
            state = _TRANSPORT_STATES.get(str(changed["State"]))
            if state is not None:
                self._on_transport(path, _mac_in_path(path), state, None, None)