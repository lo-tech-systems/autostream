"""Tests for platform/bluetooth_bluez.py's pure, dbus-free helpers —
adapter bus classification / USB-over-onboard preference (plan SS1 "Adapter
choice").

Only the pure module-level functions are exercised here: no dbus/gi
dependency, so this file runs on any Python (dev machines, the WSL test
runner) exactly like the rest of this module's helpers.
"""
from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
for _p in (REPO_ROOT / "platform",):
    _s = str(_p)
    if _s not in sys.path:
        sys.path.insert(0, _s)

import bluetooth_bluez as bluez_mod  # noqa: E402

USB_HCI0 = "/org/bluez/hci0"


def _reader(mapping: dict):
    """An injectable sysfs_reader stand-in: hci name -> resolved path (or
    None, mimicking an absent /sys entry)."""
    def _read(hci_name: str):
        return mapping.get(hci_name)
    return _read


class TestAdapterKindForPath:
    def test_usb_path_classified_as_usb(self):
        reader = _reader({"hci0": "/sys/devices/pci0000:00/.../usb3/3-1/3-1:1.0/bluetooth/hci0"})
        assert bluez_mod.adapter_kind_for_path(USB_HCI0, reader) == "usb"

    def test_platform_path_classified_as_onboard(self):
        reader = _reader({"hci0": "/sys/devices/platform/soc/fe201000.serial/bluetooth/hci0"})
        assert bluez_mod.adapter_kind_for_path(USB_HCI0, reader) == "onboard"

    def test_missing_sysfs_entry_classified_as_unknown(self):
        reader = _reader({})  # hci0 absent from the mapping -> None
        assert bluez_mod.adapter_kind_for_path(USB_HCI0, reader) == "unknown"

    def test_reader_exception_classified_as_unknown(self):
        def _raising_reader(hci_name: str):
            raise OSError("no such file")
        assert bluez_mod.adapter_kind_for_path(USB_HCI0, _raising_reader) == "unknown"

    def test_uppercase_usb_in_path_still_matched(self):
        reader = _reader({"hci0": "/sys/devices/USB3/3-1/bluetooth/hci0"})
        assert bluez_mod.adapter_kind_for_path(USB_HCI0, reader) == "usb"

    def test_default_reader_used_when_none_given(self):
        """No sysfs_reader supplied -> falls back to the real /sys reader,
        which returns None (path won't exist in a test environment) ->
        unknown, never raises."""
        assert bluez_mod.adapter_kind_for_path("/org/bluez/hci99") == "unknown"


class TestChooseAdapterPath:
    def test_prefers_usb_over_onboard(self):
        reader = _reader({
            "hci0": "/sys/devices/platform/soc/fe201000.serial/bluetooth/hci0",
            "hci1": "/sys/devices/pci0000:00/.../usb3/3-1/bluetooth/hci1",
        })
        chosen = bluez_mod.choose_adapter_path(["/org/bluez/hci0", "/org/bluez/hci1"], reader)
        assert chosen == "/org/bluez/hci1"

    def test_prefers_usb_regardless_of_list_order(self):
        reader = _reader({
            "hci0": "/sys/devices/pci0000:00/.../usb3/3-1/bluetooth/hci0",
            "hci1": "/sys/devices/platform/soc/fe201000.serial/bluetooth/hci1",
        })
        chosen = bluez_mod.choose_adapter_path(["/org/bluez/hci1", "/org/bluez/hci0"], reader)
        assert chosen == "/org/bluez/hci0"

    def test_single_onboard_adapter_falls_back_to_it(self):
        reader = _reader({"hci0": "/sys/devices/platform/soc/fe201000.serial/bluetooth/hci0"})
        chosen = bluez_mod.choose_adapter_path(["/org/bluez/hci0"], reader)
        assert chosen == "/org/bluez/hci0"

    def test_single_usb_adapter_returned(self):
        reader = _reader({"hci0": "/sys/devices/pci0000:00/.../usb3/3-1/bluetooth/hci0"})
        chosen = bluez_mod.choose_adapter_path(["/org/bluez/hci0"], reader)
        assert chosen == "/org/bluez/hci0"

    def test_no_adapters_returns_none(self):
        assert bluez_mod.choose_adapter_path([], _reader({})) is None

    def test_two_unknown_kind_adapters_falls_back_to_first(self):
        reader = _reader({})  # neither resolves -> both "unknown"
        chosen = bluez_mod.choose_adapter_path(["/org/bluez/hci0", "/org/bluez/hci1"], reader)
        assert chosen == "/org/bluez/hci0"


class TestBluezClientAdapterKindWiring:
    """BluezClient._find_adapter_path() picks via choose_adapter_path() and
    records the winner's kind on self._adapter_kind / .adapter_kind, without
    needing a real dbus connection (GetManagedObjects is stubbed)."""

    def _client_with_objects(self, objects: dict, sysfs_reader=None):
        client = bluez_mod.BluezClient(sysfs_reader=sysfs_reader)

        class _FakeObjectManager:
            def GetManagedObjects(self, dbus_interface=None, timeout=None):
                return objects

        client._object_manager = lambda: _FakeObjectManager()
        return client

    def test_find_adapter_path_prefers_usb_and_records_kind(self):
        objects = {
            "/org/bluez/hci0": {bluez_mod.ADAPTER_IFACE: {}},
            "/org/bluez/hci1": {bluez_mod.ADAPTER_IFACE: {}},
        }
        reader = _reader({
            "hci0": "/sys/devices/platform/soc/fe201000.serial/bluetooth/hci0",
            "hci1": "/sys/devices/pci0000:00/.../usb3/3-1/bluetooth/hci1",
        })
        client = self._client_with_objects(objects, sysfs_reader=reader)
        assert client._find_adapter_path() == "/org/bluez/hci1"
        assert client.adapter_kind == "usb"

    def test_find_adapter_path_none_leaves_kind_none(self):
        client = self._client_with_objects({}, sysfs_reader=_reader({}))
        assert client._find_adapter_path() is None
        assert client.adapter_kind is None

    def test_adapter_kind_none_before_connect(self):
        client = bluez_mod.BluezClient()
        assert client.adapter_kind is None


MAC_A = "AA:BB:CC:DD:EE:01"
MAC_B = "AA:BB:CC:DD:EE:02"
MAC_C = "AA:BB:CC:DD:EE:03"


class _FakeDbusExceptionsModule:
    class DBusException(Exception):
        pass


class _FakeDbusModuleForRemove:
    exceptions = _FakeDbusExceptionsModule


class TestRemoveCachedDevices:
    """bluetooth_bluez.BluezClient.remove_cached_devices(): purges every
    cached, non-paired Device1 object BlueZ already knows about (except
    keep_macs) ahead of a fresh discovery session, so devices seen in an
    earlier session re-arrive via InterfacesAdded instead of staying
    silently cached."""

    def _client_with_objects(self, objects: dict, removed: list):
        client = bluez_mod.BluezClient()
        client._dbus = _FakeDbusModuleForRemove
        client._adapter_path = "/org/bluez/hci0"

        class _FakeObjectManager:
            def GetManagedObjects(self, dbus_interface=None, timeout=None):
                return objects

        class _FakeAdapterIface:
            def RemoveDevice(self, path, timeout=None):
                removed.append(path)

        client._object_manager = lambda: _FakeObjectManager()
        client._adapter_iface = lambda: _FakeAdapterIface()
        return client

    def _device_object(self, mac: str, paired: bool = False) -> dict:
        return {bluez_mod.DEVICE_IFACE: {"Address": mac, "Paired": paired}}

    def test_removes_unpaired_devices_not_in_keep_set(self):
        objects = {
            "/org/bluez/hci0/dev_AA_BB_CC_DD_EE_01": self._device_object(MAC_A),
            "/org/bluez/hci0/dev_AA_BB_CC_DD_EE_02": self._device_object(MAC_B),
        }
        removed_paths: list = []
        client = self._client_with_objects(objects, removed_paths)

        count = client.remove_cached_devices(keep_macs=set())
        assert count == 2
        assert len(removed_paths) == 2

    def test_keeps_macs_in_keep_set(self):
        objects = {
            "/org/bluez/hci0/dev_AA_BB_CC_DD_EE_01": self._device_object(MAC_A),
            "/org/bluez/hci0/dev_AA_BB_CC_DD_EE_02": self._device_object(MAC_B),
        }
        removed_paths: list = []
        client = self._client_with_objects(objects, removed_paths)

        count = client.remove_cached_devices(keep_macs={MAC_A})
        assert count == 1
        assert removed_paths == ["/org/bluez/hci0/dev_AA_BB_CC_DD_EE_02"]

    def test_keeps_paired_devices_regardless_of_keep_set(self):
        objects = {
            "/org/bluez/hci0/dev_AA_BB_CC_DD_EE_01": self._device_object(MAC_A, paired=True),
            "/org/bluez/hci0/dev_AA_BB_CC_DD_EE_03": self._device_object(MAC_C),
        }
        removed_paths: list = []
        client = self._client_with_objects(objects, removed_paths)

        count = client.remove_cached_devices(keep_macs=set())
        assert count == 1
        assert removed_paths == ["/org/bluez/hci0/dev_AA_BB_CC_DD_EE_03"]

    def test_ignores_non_device_objects(self):
        objects = {
            "/org/bluez/hci0": {bluez_mod.ADAPTER_IFACE: {}},
            "/org/bluez/hci0/dev_AA_BB_CC_DD_EE_01": self._device_object(MAC_A),
        }
        removed_paths: list = []
        client = self._client_with_objects(objects, removed_paths)

        count = client.remove_cached_devices(keep_macs=set())
        assert count == 1

    def test_per_device_failure_logged_and_skipped(self):
        objects = {
            "/org/bluez/hci0/dev_AA_BB_CC_DD_EE_01": self._device_object(MAC_A),
            "/org/bluez/hci0/dev_AA_BB_CC_DD_EE_02": self._device_object(MAC_B),
        }
        client = self._client_with_objects(objects, removed=[])
        client._dbus = _FakeDbusModuleForRemove

        calls: list = []

        class _FailingThenOkAdapterIface:
            def RemoveDevice(self, path, timeout=None):
                calls.append(path)
                if len(calls) == 1:
                    raise _FakeDbusExceptionsModule.DBusException("org.bluez.Error.Failed")

        client._adapter_iface = lambda: _FailingThenOkAdapterIface()

        count = client.remove_cached_devices(keep_macs=set())
        assert count == 1  # one failed, one succeeded
        assert len(calls) == 2

    def test_empty_result_when_no_cached_devices(self):
        client = self._client_with_objects({}, removed=[])
        assert client.remove_cached_devices(keep_macs=set()) == 0
