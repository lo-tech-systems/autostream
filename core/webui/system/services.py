#!/usr/bin/env python3
"""webui/system/services.py

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.

The systemd service list the About page shows, and the query for the state of each unit.
"""

from __future__ import annotations

import logging
import subprocess

from autostream_bluetooth_client import bluetooth_installed, bluetooth_services_enabled

_log = logging.getLogger(__name__)


# Fixed service list; order and membership are immutable constants — never
# derived from request data.
_SERVICES = (
    ("autostream.service",              "Autostream"),
    ("autostream_monitor.service",      "Audio Monitor"),
    ("autostream_wifi_watcher.service", "Wi-Fi Watcher"),
    ("owntone.service",                 None),      # label selected at runtime
    ("vibra-mini.service",              "Vibra Mini"),
    ("nginx.service",                   "NGINX"),
)

# The one genuinely optional in-family service: spliced into _SERVICES only
# when the Bluetooth-input subsystem is installed on this appliance, always
# immediately before the NGINX row (NGINX is the fixed last entry).
# _SERVICES itself stays a fixed 6-tuple so existing call sites/tests that
# assume a static list are unaffected when the feature isn't installed
# (the common case today).
_BLUETOOTH_SERVICE_ROW = ("autostream_bluetooth.service", "Bluetooth Service")


def _effective_services() -> tuple:
    """Return _SERVICES, with the Bluetooth row spliced in before the
    trailing NGINX entry when the subsystem is installed."""
    try:
        if bluetooth_installed():
            return _SERVICES[:-1] + (_BLUETOOTH_SERVICE_ROW,) + _SERVICES[-1:]
    except Exception:
        pass
    return _SERVICES


def _collect_service_states(owntone_backend_id: str, service_versions: dict) -> list:
    """Query systemd for the fixed service units and return state list.

    Units queried are _SERVICES plus the Bluetooth row when the subsystem is
    installed (_effective_services()); the six-unit case is unchanged from
    before this feature existed.
    """
    services_list = _effective_services()
    unit_names = [unit for unit, _ in services_list]
    parsed: dict = {}
    try:
        result = subprocess.run(
            [
                "systemctl", "show", "--no-pager",
                "--property=Id",
                "--property=ActiveState",
            ] + unit_names,
            capture_output=True,
            text=True,
            timeout=2.0,
            check=False,
        )
        parsed = _parse_systemctl_output(result.stdout or "")
    except Exception:
        _log.debug("about/system: systemctl query failed", exc_info=True)

    services = []
    for unit, label in services_list:
        if label is None:
            label = "OwnTone Mini" if owntone_backend_id == "owntone-mini" else "OwnTone"
        block = parsed.get(unit, {})
        active_state = block.get("ActiveState", "")
        if unit == _BLUETOOTH_SERVICE_ROW[0]:
            state = _bluetooth_row_state(active_state)
        else:
            state = "ok" if active_state == "active" else "failed"
        entry: dict = {"unit": unit, "label": label, "state": state}
        version = service_versions.get(unit)
        if version and version not in ("unknown", ""):
            entry["version"] = version
        services.append(entry)
    return services


def _bluetooth_row_state(active_state: str) -> str:
    """Bluetooth row's three-way state, distinct from every other row's
    plain ok/failed mapping.

    systemd reports the same ActiveState ("inactive") for "unit never
    enabled" and "enabled but not currently running", so the row would
    otherwise render a never-installed-in-anger service as "Failed".
    ``bluetooth_services_enabled()`` disambiguates the two: a disabled unit
    reads "disabled" regardless of ActiveState; only once enabled does the
    ordinary active/not-active check (mirroring every other row) apply.
    """
    try:
        enabled = bluetooth_services_enabled()
    except Exception:
        enabled = False
    if not enabled:
        return "disabled"
    return "ok" if active_state == "active" else "failed"


def _parse_systemctl_output(stdout: str) -> dict:
    """Parse blank-line-separated systemctl show output into {Id: {prop: val}}."""
    blocks: dict = {}
    current: dict = {}
    for line in stdout.splitlines():
        line = line.rstrip()
        if not line:
            if current:
                unit_id = current.get("Id", "")
                if unit_id:
                    blocks[unit_id] = current
                current = {}
        elif "=" in line:
            key, _, value = line.partition("=")
            current[key.strip()] = value
    if current:
        unit_id = current.get("Id", "")
        if unit_id:
            blocks[unit_id] = current
    return blocks
