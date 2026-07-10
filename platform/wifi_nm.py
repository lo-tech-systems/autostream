#!/usr/bin/python3
"""wifi_nm.py

Copyright (c) 2025 Lo-tech Systems Limited. All rights reserved.

The one place that invokes ``nmcli`` for the Autostream Wi-Fi watcher.  Every
method passes an explicit ``run_cmd(timeout=…)`` bound, so there is no unbounded
NetworkManager code path — the IF-1 "bound every subprocess" convention becomes
structural rather than a per-site discipline.

``NMClient`` is instantiated once at watcher startup with the two watcher timeout
constants (the activation timeout for ``nmcli connection up`` and the quick
timeout for add/modify/delete/disconnect).  Methods return what their call sites
consume — a ``CompletedProcess`` for command sites, or a parsed value for the
query helpers, whose parsing stays in the pure ``autostream_wifi_network``
functions this client calls.  Deployed beside the watcher on the system Python.
"""
from __future__ import annotations

import logging
from typing import Optional

from autostream_sysutils import run_cmd
import autostream_wifi_network as wifi_net

logger = logging.getLogger(__name__)


def _run_teardown(cmd: list, benign_substring: str, timeout: float):
    """Run an idempotent nmcli teardown command (delete/disconnect).

    A nonzero exit whose stderr contains *benign_substring* means the goal
    state already holds (connection absent / device inactive) — logged at
    DEBUG, not as a failure.  Any other nonzero exit keeps the usual WARNING.
    """
    r = run_cmd(cmd, timeout=timeout, warn_on_failure=False)
    if r.returncode != 0:
        stderr = (r.stderr or "").strip()
        if benign_substring in stderr:
            logger.debug(
                "Teardown already satisfied: %s (rc=%s)", " ".join(cmd), r.returncode)
        else:
            logger.warning(
                "Command failed: %s (rc=%s, stderr=%s)", " ".join(cmd), r.returncode, stderr)
    return r


class NMClient:
    """Bounded wrapper over every ``nmcli`` invocation the watcher needs."""

    def __init__(self, activate_timeout: float, quick_timeout: float) -> None:
        # activate_timeout bounds `nmcli connection up` (the join waits on NM);
        # quick_timeout bounds add / modify / delete / device disconnect.
        self._activate_timeout = activate_timeout
        self._quick_timeout = quick_timeout

    # ---- activation ----

    def activate(self, uuid: str, name: str = "", ifname: str = ""):
        """`nmcli connection up` (uuid preferred, else name), optional ifname pin."""
        return run_cmd(wifi_net.activate_connection_cmd(uuid, name, ifname),
                       timeout=self._activate_timeout)

    def activate_ident(self, ident: list, timeout: Optional[float] = None):
        """`nmcli connection up <ident...>` for a pre-built identifier list
        (e.g. ``["uuid", uuid]`` or ``["id", name]``)."""
        return run_cmd(["nmcli", "connection", "up", *ident],
                       timeout=self._activate_timeout if timeout is None else timeout)

    def activate_ap(self, con_name: str, ifname: str):
        """Bring up the AP connection on *ifname*."""
        return run_cmd(["nmcli", "connection", "up", con_name, "ifname", ifname],
                       timeout=self._activate_timeout)

    # ---- restriction clearing ----

    def clear_restrictions(self, uuid: str, keys):
        """Clear the given cross-adapter restriction keys on a profile."""
        return run_cmd(wifi_net.clear_restrictions_cmd(uuid, keys),
                       timeout=self._quick_timeout)

    # ---- BSSID pin ----

    def wifi_bssid_scan(self, ifname: str, rescan: bool) -> Optional[list]:
        """Bounded BSSID-level scan of *ifname*; parsed rows, or None on failure."""
        if rescan:
            run_cmd(wifi_net.rescan_cmd(ifname), timeout=wifi_net.NMCLI_BSSID_SCAN_TIMEOUT)
        r = run_cmd(wifi_net.bssid_scan_cmd(ifname, rescan),
                    timeout=wifi_net.NMCLI_BSSID_SCAN_TIMEOUT)
        if r.returncode != 0:
            return None
        return wifi_net.parse_bssid_scan_output(r.stdout)

    def set_bssid(self, uuid: str, bssid: str):
        """Pin (or, with an empty *bssid*, clear) a profile's BSSID property."""
        return run_cmd(wifi_net.set_bssid_cmd(uuid, bssid),
                       timeout=self._quick_timeout)

    # ---- deletion ----

    def delete_connection(self, ident: str):
        """Delete a saved connection by bare name or uuid (idempotent:
        an already-absent connection is the goal state, not a failure)."""
        return _run_teardown(["nmcli", "connection", "delete", ident],
                             "unknown connection", self._quick_timeout)

    def delete_by_uuid(self, uuid: str):
        """Delete a saved connection explicitly by uuid (idempotent, as
        ``delete_connection``)."""
        return _run_teardown(wifi_net.delete_connection_cmd(uuid),
                             "unknown connection", self._quick_timeout)

    # ---- candidate profile setup ----

    def run_candidate_setup(self, cmd: list, log_cmd: Optional[list] = None):
        """Run one add/modify step of the rollback-safe candidate sequence."""
        return run_cmd(cmd, log_cmd=log_cmd, timeout=self._quick_timeout)

    # ---- device disconnect ----

    def disconnect_device(self, ifname: str):
        """`nmcli device disconnect <ifname>` (idempotent: NM may already
        have deactivated the device, e.g. when the single client profile was
        re-activated on another adapter — "not active" is the goal state)."""
        return _run_teardown(["nmcli", "device", "disconnect", ifname],
                             "not active", self._quick_timeout)

    # ---- AP lifecycle ----

    def add_ap_connection(self, ifname: str, ssid: str, con_name: str,
                          address: str = "192.168.4.1/24"):
        """Create the AP-mode connection on *ifname* broadcasting *ssid*."""
        return run_cmd([
            "nmcli", "connection", "add",
            "type", "wifi",
            "ifname", ifname,
            "con-name", con_name,
            "autoconnect", "no",
            "ssid", ssid,
            "802-11-wireless.mode", "ap",
            "ipv4.method", "manual",
            "ipv4.addresses", address,
            "ipv4.never-default", "yes",
            "ipv6.method", "ignore",
        ], timeout=self._quick_timeout)

    # ---- profile admin ----

    def set_autoconnect_no(self, uuid: str, name: str = ""):
        """Disable NM autoconnect on a profile (uuid preferred, else name)."""
        return run_cmd(wifi_net.set_autoconnect_no_cmd(uuid, name),
                       timeout=self._quick_timeout)
