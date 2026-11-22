"""autostream_bluetooth_facts.py

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.

Unprivileged, non-socket fact-checks for the optional Bluetooth-input
subsystem: whether the unit is installed at all, whether it is
enabled/running, whether the onboard radio (as opposed to a USB
adapter) is in use, and whether this board may use the onboard radio at
all.

Split out of ``core/autostream_bluetooth_client.py``, which re-exports
these names for existing importers. These three functions are plain
filesystem/systemctl/text-scan reads, not socket I/O to the
``autostream_bluetooth`` peer daemon, so they belong next to the other
unprivileged fact-checks rather than inside the socket-adapter module.
"""

from __future__ import annotations

import logging
import os
import subprocess
from typing import Optional

logger = logging.getLogger(__name__)

_DEFAULT_UNIT_PATH = "/etc/systemd/system/autostream_bluetooth.service"
_DEFAULT_BOOT_CONFIG_PATH = "/boot/firmware/config.txt"
_DISABLE_BT_OVERLAY = "dtoverlay=disable-bt"
# A power board that takes the PL011 UART moves the onboard radio to the
# mini UART, where its audio breaks up badly enough to be unusable.
_MINIUART_BT_OVERLAY = "dtoverlay=miniuart-bt"

ONBOARD_RADIO_REFUSED_REASON = (
    "Onboard Bluetooth is not available with this appliance's power board; "
    "plug in a USB adapter."
)


def bluetooth_installed(unit_path: Optional[str] = None) -> bool:
    """Return True when the Bluetooth-input systemd unit is installed.

    The installer always writes the unit file (disabled) once the
    Bluetooth-input subsystem is present on this build; this is a plain
    filesystem check, not a systemd query, so it works even while the
    service itself is stopped/disabled. Path is overridable via
    ``AUTOSTREAM_BT_UNIT_PATH`` (or the ``unit_path`` argument, for tests).
    """
    path = (
        unit_path
        or os.environ.get("AUTOSTREAM_BT_UNIT_PATH", "").strip()
        or _DEFAULT_UNIT_PATH
    )
    try:
        return os.path.isfile(path)
    except OSError:
        return False


def bluetooth_services_enabled(unit_name: str = "autostream_bluetooth") -> bool:
    """Return True when the Bluetooth-input systemd unit is enabled.

    Runs a bounded, non-raising ``systemctl is-enabled --quiet`` check
    (``check=False``): any failure -- systemctl absent, unit absent, timeout,
    unexpected exit code -- resolves to False rather than raising, so
    callers (page renders, status routes, gating helpers) never need
    daemon-specific error handling here.
    """
    try:
        result = subprocess.run(
            ["systemctl", "is-enabled", "--quiet", unit_name],
            check=False,
            timeout=3,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return result.returncode == 0


def bluetooth_onboard_enabled(config_path: Optional[str] = None) -> bool:
    """Return True when the onboard Bluetooth radio is in use.

    The onboard radio is disabled by default on every appliance via a
    ``dtoverlay=disable-bt`` line in ``/boot/firmware/config.txt`` (written
    universally at install time); the "Use onboard bluetooth device" toggle
    removes that line to re-enable it. The file is world-readable, so this
    is a plain text scan -- a missing file (unexpected, but tolerated)
    resolves to False, matching the appliance-wide default. Path is
    overridable via ``AUTOSTREAM_BOOT_CONFIG_PATH`` (or ``config_path``, for
    tests).
    """
    try:
        with open(_boot_config_path(config_path), "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                if line.strip() == _DISABLE_BT_OVERLAY:
                    return False
        return True
    except OSError:
        return False


def _boot_config_path(config_path: Optional[str]) -> str:
    return (
        config_path
        or os.environ.get("AUTOSTREAM_BOOT_CONFIG_PATH", "").strip()
        or _DEFAULT_BOOT_CONFIG_PATH
    )


def onboard_radio_refused(config_path: Optional[str] = None) -> Optional[str]:
    """Return the reason the onboard radio may not be enabled on this
    board, or None when it may.

    Refused when ``/boot/firmware/config.txt`` loads the ``miniuart-bt``
    overlay (with or without parameters): the board's power hardware has
    the PL011 UART, and the radio on the mini UART loses too much audio to
    be any use. Commented-out lines do not count. A missing or unreadable
    file refuses nothing. Path is overridable as for
    ``bluetooth_onboard_enabled``.
    """
    try:
        with open(_boot_config_path(config_path), "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                text = line.strip()
                if text == _MINIUART_BT_OVERLAY or text.startswith(_MINIUART_BT_OVERLAY + ","):
                    return ONBOARD_RADIO_REFUSED_REASON
    except OSError:
        return None
    return None
