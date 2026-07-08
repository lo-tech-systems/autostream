"""First-boot import, autoconnect migration, and configured-network
reconnect/UUID resolution."""
from __future__ import annotations

import contextlib
import json
import os
import sys
import threading
import time
from contextlib import ExitStack
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch, call
import ipaddress

import pytest

from _wifi_fixtures import (
    _get_watcher,
    _isolate_reboot_guard,
    _reset_activation_worker,
    _restore_root_log_level,
    flask_client,
    watcher,
)
from _wifi_fixtures import _adapter


class TestFirstBootImport:
    """WP-5 — first-boot Wi-Fi profile import (the one destructive step)."""

    def _adapter(self, ifname):
        a = MagicMock()
        a.ifname = ifname
        return a

    def _deleted_idents(self, by_uuid, by_name):
        # Every saved profile deleted, whether by uuid or bare name.
        return ([c.args[0] for c in by_uuid.call_args_list]
                + [c.args[0] for c in by_name.call_args_list])

    def test_single_active_retained_others_deleted(self, watcher, tmp_path):
        marker = str(tmp_path / "first-boot-import.done")
        a = self._adapter("wlan0")
        with patch.object(watcher.CONFIG_CTX, "FIRST_BOOT_IMPORT_MARKER", marker), \
             patch.object(watcher.wifi_net, "discover_adapters", return_value=[a]), \
             patch.object(watcher.wifi_net, "get_active_wifi_connection_name", return_value="HomeNet"), \
             patch.object(watcher.wifi_net, "resolve_connection_uuid_for_name", return_value="uuid-home"), \
             patch.object(watcher.CONFIG_CTX, "_commit_network_state") as commit, \
             patch.object(watcher.wifi_net, "list_wifi_connection_profiles",
                          return_value=[("uuid-home", "HomeNet"), ("uuid-old", "OldNet"),
                                        ("uuid-dev", "DevNet")]), \
             patch.object(watcher.wifi_net, "wifi_profile_mode", return_value="infrastructure"), \
             patch.object(watcher.nm, "set_autoconnect_no", return_value=MagicMock(returncode=0, stderr="")), \
             patch.object(watcher.nm, "delete_by_uuid", return_value=MagicMock(returncode=0, stderr="")) as del_uuid, \
             patch.object(watcher.nm, "delete_connection", return_value=MagicMock(returncode=0, stderr="")) as del_name:
            watcher.import_first_boot_wifi_profile()
        commit.assert_called_once_with("HomeNet", "uuid-home")
        deleted = self._deleted_idents(del_uuid, del_name)
        assert "uuid-old" in deleted
        assert "uuid-dev" in deleted
        assert "uuid-home" not in deleted   # retained, never deleted
        assert os.path.exists(marker)

    def test_multi_active_retains_default_route_carrier(self, watcher, tmp_path):
        marker = str(tmp_path / "first-boot-import.done")
        a0, a1 = self._adapter("wlan0"), self._adapter("wlan1")
        names = {"wlan0": "NetA", "wlan1": "NetB"}
        gw = {"wlan0": "", "wlan1": "192.168.1.1"}
        with patch.object(watcher.CONFIG_CTX, "FIRST_BOOT_IMPORT_MARKER", marker), \
             patch.object(watcher.wifi_net, "discover_adapters", return_value=[a0, a1]), \
             patch.object(watcher.wifi_net, "get_active_wifi_connection_name",
                          side_effect=lambda i: names[i]), \
             patch.object(watcher.wifi_net, "default_gateway_ipv4", side_effect=lambda i: gw[i]), \
             patch.object(watcher.wifi_net, "resolve_connection_uuid_for_name",
                          side_effect=lambda n: "uuid-" + n), \
             patch.object(watcher.CONFIG_CTX, "_commit_network_state") as commit, \
             patch.object(watcher.wifi_net, "list_wifi_connection_profiles",
                          return_value=[("uuid-NetA", "NetA"), ("uuid-NetB", "NetB")]), \
             patch.object(watcher.wifi_net, "wifi_profile_mode", return_value="infrastructure"), \
             patch.object(watcher.nm, "set_autoconnect_no", return_value=MagicMock(returncode=0, stderr="")), \
             patch.object(watcher.nm, "delete_by_uuid", return_value=MagicMock(returncode=0, stderr="")) as del_uuid, \
             patch.object(watcher.nm, "delete_connection", return_value=MagicMock(returncode=0, stderr="")) as del_name:
            watcher.import_first_boot_wifi_profile()
        # NetB carries the default route -> retained; NetA deleted.
        commit.assert_called_once_with("NetB", "uuid-NetB")
        deleted = self._deleted_idents(del_uuid, del_name)
        assert "uuid-NetA" in deleted
        assert "uuid-NetB" not in deleted

    def test_no_active_profile_deletes_nothing(self, watcher, tmp_path):
        marker = str(tmp_path / "first-boot-import.done")
        a = self._adapter("wlan0")
        with patch.object(watcher.CONFIG_CTX, "FIRST_BOOT_IMPORT_MARKER", marker), \
             patch.object(watcher.wifi_net, "discover_adapters", return_value=[a]), \
             patch.object(watcher.wifi_net, "get_active_wifi_connection_name", return_value=""), \
             patch.object(watcher.CONFIG_CTX, "_commit_network_state") as commit, \
             patch.object(watcher.wifi_net, "list_wifi_connection_profiles") as lst, \
             patch.object(watcher, "run_cmd") as rc:
            watcher.import_first_boot_wifi_profile()
        commit.assert_not_called()
        lst.assert_not_called()
        rc.assert_not_called()
        assert os.path.exists(marker)   # marker still written (idempotent skip next boot)

    def test_already_managed_upgrade_deletes_nothing(self, watcher, tmp_path):
        # An already-managed device: exactly one profile, committed and active.
        marker = str(tmp_path / "first-boot-import.done")
        a = self._adapter("wlan0")
        with patch.object(watcher.CONFIG_CTX, "FIRST_BOOT_IMPORT_MARKER", marker), \
             patch.object(watcher.wifi_net, "discover_adapters", return_value=[a]), \
             patch.object(watcher.wifi_net, "get_active_wifi_connection_name", return_value="Managed"), \
             patch.object(watcher.wifi_net, "resolve_connection_uuid_for_name", return_value="uuid-m"), \
             patch.object(watcher.CONFIG_CTX, "_commit_network_state") as commit, \
             patch.object(watcher.wifi_net, "list_wifi_connection_profiles",
                          return_value=[("uuid-m", "Managed")]), \
             patch.object(watcher.wifi_net, "wifi_profile_mode", return_value="infrastructure"), \
             patch.object(watcher.nm, "set_autoconnect_no", return_value=MagicMock(returncode=0, stderr="")), \
             patch.object(watcher.nm, "delete_by_uuid", return_value=MagicMock(returncode=0, stderr="")) as del_uuid, \
             patch.object(watcher.nm, "delete_connection", return_value=MagicMock(returncode=0, stderr="")) as del_name:
            watcher.import_first_boot_wifi_profile()
        commit.assert_called_once_with("Managed", "uuid-m")
        assert self._deleted_idents(del_uuid, del_name) == []   # nothing else to delete
        assert os.path.exists(marker)

    def test_ap_hotspot_profile_never_deleted(self, watcher, tmp_path):
        marker = str(tmp_path / "first-boot-import.done")
        a = self._adapter("wlan0")
        modes = {"Hotspot": "ap", "HomeNet": "infrastructure", "OldNet": "infrastructure"}
        with patch.object(watcher.CONFIG_CTX, "FIRST_BOOT_IMPORT_MARKER", marker), \
             patch.object(watcher.wifi_net, "discover_adapters", return_value=[a]), \
             patch.object(watcher.wifi_net, "get_active_wifi_connection_name", return_value="HomeNet"), \
             patch.object(watcher.wifi_net, "resolve_connection_uuid_for_name", return_value="uuid-home"), \
             patch.object(watcher.CONFIG_CTX, "_commit_network_state"), \
             patch.object(watcher.wifi_net, "list_wifi_connection_profiles",
                          return_value=[("uuid-home", "HomeNet"), ("uuid-hs", "Hotspot"),
                                        ("uuid-old", "OldNet")]), \
             patch.object(watcher.wifi_net, "wifi_profile_mode",
                          side_effect=lambda ident: modes.get("Hotspot" if "hs" in ident else
                                                              ("OldNet" if "old" in ident else "HomeNet"),
                                                              "infrastructure")), \
             patch.object(watcher.nm, "set_autoconnect_no", return_value=MagicMock(returncode=0, stderr="")), \
             patch.object(watcher.nm, "delete_by_uuid", return_value=MagicMock(returncode=0, stderr="")) as del_uuid, \
             patch.object(watcher.nm, "delete_connection", return_value=MagicMock(returncode=0, stderr="")) as del_name:
            watcher.import_first_boot_wifi_profile()
        deleted = self._deleted_idents(del_uuid, del_name)
        assert "uuid-old" in deleted
        assert "uuid-hs" not in deleted   # AP profile never deleted

    def test_delete_failure_logged_and_continues(self, watcher, tmp_path):
        marker = str(tmp_path / "first-boot-import.done")
        a = self._adapter("wlan0")

        def _del(uuid):
            return (MagicMock(returncode=1, stderr="boom") if uuid == "uuid-old"
                    else MagicMock(returncode=0, stderr=""))

        with patch.object(watcher.CONFIG_CTX, "FIRST_BOOT_IMPORT_MARKER", marker), \
             patch.object(watcher.wifi_net, "discover_adapters", return_value=[a]), \
             patch.object(watcher.wifi_net, "get_active_wifi_connection_name", return_value="HomeNet"), \
             patch.object(watcher.wifi_net, "resolve_connection_uuid_for_name", return_value="uuid-home"), \
             patch.object(watcher.CONFIG_CTX, "_commit_network_state"), \
             patch.object(watcher.wifi_net, "list_wifi_connection_profiles",
                          return_value=[("uuid-home", "HomeNet"), ("uuid-old", "OldNet"),
                                        ("uuid-dev", "DevNet")]), \
             patch.object(watcher.wifi_net, "wifi_profile_mode", return_value="infrastructure"), \
             patch.object(watcher.nm, "set_autoconnect_no", return_value=MagicMock(returncode=0, stderr="")), \
             patch.object(watcher.nm, "delete_by_uuid", side_effect=_del) as del_uuid, \
             patch.object(watcher.nm, "delete_connection", return_value=MagicMock(returncode=0, stderr="")) as del_name:
            watcher.import_first_boot_wifi_profile()   # must not raise
        deleted = self._deleted_idents(del_uuid, del_name)
        # Both deletions attempted despite the first failing.
        assert "uuid-old" in deleted
        assert "uuid-dev" in deleted
        assert os.path.exists(marker)

    def test_skips_when_marker_present(self, watcher, tmp_path):
        marker = tmp_path / "first-boot-import.done"
        marker.write_text("done")
        with patch.object(watcher, "FIRST_BOOT_IMPORT_MARKER", str(marker)), \
             patch.object(watcher.wifi_net, "discover_adapters") as disc:
            watcher.import_first_boot_wifi_profile()
        disc.assert_not_called()   # marker present -> no work at all


class TestConnectToConfiguredWifiUuid:
    """A-WP6: the steady-state reconnect resolves the UUID and clears
    cross-adapter restrictions (inconsistency 4), fire-and-forget (no wait)."""

    def test_reconnect_carries_uuid_and_clears_restrictions_no_wait(self, watcher):
        with patch.object(watcher.CONFIG_CTX, "get_configured_network_state",
                          return_value=watcher.wifi_net.NetworkState("Home", "")), \
             patch.object(watcher.CONFIG_CTX, "is_wifi_client_healthy", return_value=False), \
             patch.object(watcher.wifi_net, "resolve_connection_uuid_for_name",
                          return_value="resolved-uuid"), \
             patch.object(watcher.wifi_net, "save_network_state"), \
             patch.object(watcher.nm, "clear_restrictions") as clear, \
             patch.object(watcher.nm, "activate_ident",
                          return_value=MagicMock(returncode=0, stderr="")) as activate, \
             patch.object(watcher, "wait_for_connection") as wait:
            ok = watcher.connect_to_configured_wifi()
        assert ok is True
        wait.assert_not_called()  # fire-and-forget: no blocking IPv4 wait in the loop
        # restrictions cleared with the resolved UUID, and the activation carries it.
        clear.assert_called_once_with("resolved-uuid", watcher.wifi_net.CROSS_ADAPTER_RESTRICTIONS)
        assert activate.call_args[0][0] == ["uuid", "resolved-uuid"]

    def test_healthy_returns_early_without_activation(self, watcher):
        calls = []
        with patch.object(watcher.CONFIG_CTX, "get_configured_network_state",
                          return_value=watcher.wifi_net.NetworkState("Home", "uuid-1")), \
             patch.object(watcher.CONFIG_CTX, "is_wifi_client_healthy", return_value=True), \
             patch.object(watcher, "run_cmd",
                          side_effect=lambda c, *a, **k: calls.append(c) or MagicMock(returncode=0)):
            ok = watcher.connect_to_configured_wifi()
        assert ok is True
        assert not any(isinstance(c, list) and "up" in c for c in calls), (
            "healthy path must not issue nmcli connection up"
        )


class TestResolveCommittedUuid:
    """_resolve_committed_uuid() resolves and persists missing UUIDs so that
    cross-adapter restriction clearing is not skipped for legacy profiles."""

    def _state(self, watcher, name="HomeNetwork", uuid=""):
        return watcher.wifi_net.NetworkState(connection_name=name, connection_uuid=uuid)

    def test_returns_uuid_when_already_present(self, watcher):
        state = self._state(watcher, uuid="existing-uuid")
        with patch.object(watcher.wifi_net, "resolve_connection_uuid_for_name") as resolve, \
             patch.object(watcher.wifi_net, "save_network_state") as save:
            result = watcher._resolve_committed_uuid(state)
        assert result == "existing-uuid"
        resolve.assert_not_called()
        save.assert_not_called()

    def test_resolves_and_persists_when_uuid_empty(self, watcher):
        state = self._state(watcher, uuid="")
        with patch.object(watcher.wifi_net, "resolve_connection_uuid_for_name",
                          return_value="resolved-uuid") as resolve, \
             patch.object(watcher.wifi_net, "save_network_state") as save:
            result = watcher._resolve_committed_uuid(state)
        assert result == "resolved-uuid"
        resolve.assert_called_once_with("HomeNetwork")
        save.assert_called_once()
        saved_state = save.call_args[0][0]
        assert saved_state.connection_uuid == "resolved-uuid"
        assert saved_state.connection_name == "HomeNetwork"

    def test_returns_empty_when_resolution_fails(self, watcher):
        state = self._state(watcher, uuid="")
        with patch.object(watcher.wifi_net, "resolve_connection_uuid_for_name",
                          return_value="") as resolve, \
             patch.object(watcher.wifi_net, "save_network_state") as save:
            result = watcher._resolve_committed_uuid(state)
        assert result == ""
        resolve.assert_called_once_with("HomeNetwork")
        save.assert_not_called()

    def test_returns_empty_when_name_empty(self, watcher):
        state = self._state(watcher, name="", uuid="")
        with patch.object(watcher.wifi_net, "resolve_connection_uuid_for_name") as resolve:
            result = watcher._resolve_committed_uuid(state)
        assert result == ""
        resolve.assert_not_called()

    def test_still_returns_uuid_when_persist_fails(self, watcher):
        """A persistence failure must not suppress the resolved UUID — the
        restriction clear should still proceed using the in-memory value."""
        state = self._state(watcher, uuid="")
        with patch.object(watcher.wifi_net, "resolve_connection_uuid_for_name",
                          return_value="resolved-uuid"), \
             patch.object(watcher.wifi_net, "save_network_state",
                          side_effect=OSError("disk full")):
            result = watcher._resolve_committed_uuid(state)
        assert result == "resolved-uuid"

    def test_activate_committed_on_resolves_uuid_before_restriction_clear(self, watcher):
        """When the committed state has an empty UUID, _activate_committed_on
        must resolve it and clear restrictions before activating."""
        with patch.object(watcher.ACTIVATION_CTX, "get_configured_network_state") as gcns, \
             patch.object(watcher.wifi_net, "resolve_connection_uuid_for_name",
                          return_value="resolved-uuid"), \
             patch.object(watcher.wifi_net, "save_network_state"), \
             patch.object(watcher.nm, "clear_restrictions") as clear, \
             patch.object(watcher.nm, "activate", return_value=MagicMock(returncode=0)), \
             patch.object(watcher.ACTIVATION_CTX, "wait_for_connection", return_value=True), \
             patch.object(watcher.ACTIVATION_CTX, "is_wifi_client_healthy", return_value=True):
            gcns.return_value = watcher.wifi_net.NetworkState(
                connection_name="HomeNetwork", connection_uuid=""
            )
            watcher._activate_committed_on("wlan1")

        clear.assert_called_once_with("resolved-uuid", watcher.wifi_net.CROSS_ADAPTER_RESTRICTIONS)


class TestClientProfileAutoconnectMigration:
    """D-WP2 — the startup migration disables NM autoconnect on every managed
    non-AP Wi-Fi client profile (self-healing), skipping AP profiles."""

    def _res(self, rc=0, stderr=""):
        return MagicMock(returncode=rc, stderr=stderr)

    def test_modifies_client_profiles_and_skips_ap(self, watcher):
        profiles = [("uuid-1", "Home"), ("uuid-ap", "autostream-Hotspot"),
                    ("uuid-2", "Guest")]
        modes = {"uuid-1": "infrastructure", "uuid-ap": "ap", "uuid-2": ""}
        modified = []

        def fake_modify(uuid, name=""):
            modified.append(uuid)
            return self._res()

        with patch.object(watcher.wifi_net, "list_wifi_connection_profiles",
                          return_value=profiles), \
             patch.object(watcher.wifi_net, "wifi_profile_mode",
                          side_effect=lambda ident: modes[ident]), \
             patch.object(watcher.nm, "set_autoconnect_no", side_effect=fake_modify):
            count = watcher.migrate_client_profiles_autoconnect_no()

        assert count == 2
        assert modified == ["uuid-1", "uuid-2"]   # AP profile skipped

    def test_no_profiles_is_noop(self, watcher):
        with patch.object(watcher.wifi_net, "list_wifi_connection_profiles",
                          return_value=[]), \
             patch.object(watcher, "run_cmd") as run:
            count = watcher.migrate_client_profiles_autoconnect_no()
        assert count == 0
        run.assert_not_called()

    def test_per_profile_failure_does_not_abort_sweep(self, watcher):
        profiles = [("uuid-1", "Home"), ("uuid-2", "Guest")]

        def fake_modify(uuid, name=""):
            return self._res(rc=1, stderr="boom") if uuid == "uuid-1" else self._res()

        with patch.object(watcher.wifi_net, "list_wifi_connection_profiles",
                          return_value=profiles), \
             patch.object(watcher.wifi_net, "wifi_profile_mode",
                          return_value="infrastructure"), \
             patch.object(watcher.nm, "set_autoconnect_no", side_effect=fake_modify):
            count = watcher.migrate_client_profiles_autoconnect_no()
        assert count == 1   # uuid-1 failed, uuid-2 succeeded, sweep continued

    def test_sweep_converts_by_setting_autoconnect_no(self, watcher):
        # IF-4 (b): the conversion is the point — the sweep must set
        # connection.autoconnect=no on a client profile (idempotent, so it
        # converts a would-be autoconnect=yes profile), while skipping AP
        # profiles.  The command shape (modify … connection.autoconnect no) is
        # pinned by the NMClient unit test; here we pin that the client profile is
        # targeted and the AP profile is skipped.
        profiles = [("uuid-yes", "Home"), ("uuid-ap", "autostream-Hotspot")]
        modes = {"uuid-yes": "infrastructure", "uuid-ap": "ap"}
        issued = []

        def fake_modify(uuid, name=""):
            issued.append((uuid, name))
            return self._res()

        with patch.object(watcher.wifi_net, "list_wifi_connection_profiles",
                          return_value=profiles), \
             patch.object(watcher.wifi_net, "wifi_profile_mode",
                          side_effect=lambda ident: modes[ident]), \
             patch.object(watcher.nm, "set_autoconnect_no", side_effect=fake_modify):
            count = watcher.migrate_client_profiles_autoconnect_no()

        assert count == 1
        assert issued == [("uuid-yes", "Home")]        # client only; AP skipped
