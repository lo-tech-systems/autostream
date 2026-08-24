#!/usr/bin/env python3
"""autostream_bluetooth_client.py

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.

Thin client for the optional ``autostream_bluetooth`` peer service's
Unix-socket JSON API.

Mirrors ``core.autostream_core.MonitorClient``'s connect / bounded-timeout /
quiet-failure shape, but the daemon's wire contract is "one JSON request per
connection" rather than MonitorClient's long-lived session: each public
method here opens a fresh socket, writes one newline-terminated JSON
request, reads one newline-terminated JSON reply, and closes -- there is no
persistent connection state to manage between calls.  Any failure (socket
absent, daemon down, timeout, malformed reply) is swallowed and surfaced as
``None`` so callers (the relabel hook, the web routes, the background scan
loop) can degrade gracefully without daemon-specific error handling.

Also hosts the pinned wire/ALSA constants shared between the coordinator
(relabel hook) and the web UI, and ``classify_loopback_hw()``/
``is_loopback_playback()``, the small amount of loopback-hw-string
classification logic built directly on those constants:

  - ``BLUETOOTH_CAPTURE_DEVICE`` / ``BLUETOOTH_PLAYBACK_DEVICE`` -- the two
    sides of the ``snd-aloop`` pseudo-device.
  - ``classify_loopback_hw()`` / ``is_loopback_playback()`` -- the small
    amount of logic the device-list relabel hook needs.

The three unprivileged fact-checks (``bluetooth_installed()`` /
``bluetooth_services_enabled()`` / ``bluetooth_onboard_enabled()``) and the
four presentation-string builders (``bluetooth_card_summary()`` /
``bluetooth_paired_row_text()`` / ``bluetooth_input_fragment_text()`` /
``bluetooth_capture_label()``) that used to live in this module have moved
to ``autostream_bluetooth_facts.py`` and
``autostream_bluetooth_presentation.py`` respectively -- unprivileged reads
and pure string formatting are not socket-adapter I/O. They are
re-imported and re-exported here so existing
``from autostream_bluetooth_client import ...`` call sites keep working
unchanged.
"""

from __future__ import annotations

import json
import logging
import os
import socket
from typing import Optional

from autostream_bluetooth_facts import (  # noqa: F401 -- re-exported for existing importers
    bluetooth_installed,
    bluetooth_onboard_enabled,
    bluetooth_services_enabled,
)
from autostream_bluetooth_presentation import (  # noqa: F401 -- re-exported for existing importers
    bluetooth_capture_label,
    bluetooth_card_summary,
    bluetooth_input_fragment_text,
    bluetooth_paired_row_text,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Pinned constants -- shared between the daemon, the coordinator relabel
# hook, and the web UI, so they must stay in lock-step with the socket unit,
# modprobe.d config, and the daemon's own copies.
# ---------------------------------------------------------------------------

DEFAULT_SOCKET_PATH = "/run/autostream-bluetooth/bluetooth.sock"

# Client-side fallback for the About page's per-service version display,
# used whenever the daemon can't be queried directly (disabled/stopped/never
# started). Kept in sync with the daemon's own copy
# (platform/bluetooth_service.py's BLUETOOTH_SERVICE_VERSION) -- both must
# be bumped together.
BLUETOOTH_SERVICE_VERSION = "0.5.3"

# ALSA loopback card id, fixed at install time via modprobe.d.
BLUETOOTH_CARD_ID = "ASBT"

# The two loopback subdevices: DEV=0 is the playback side the pump feeds,
# DEV=1 is the capture side the monitor opens.  Both are hw:-prefixed and
# pass the monitor's existing capture-device enumeration/validation
# unchanged -- only the Python relabel hook (below) treats them specially.
BLUETOOTH_PLAYBACK_DEVICE = f"hw:CARD={BLUETOOTH_CARD_ID},DEV=0"
BLUETOOTH_CAPTURE_DEVICE = f"hw:CARD={BLUETOOTH_CARD_ID},DEV=1"


def get_bluetooth_socket_path() -> str:
    """Return the configured autostream_bluetooth socket path.

    Overridable via ``AUTOSTREAM_BLUETOOTH_SOCKET`` (mirrors
    ``get_monitor_socket_path()``'s ``AUTOSTREAM_MONITOR_SOCKET`` pattern),
    which is also how tests point the client at a scratch socket.
    """
    return (
        os.environ.get("AUTOSTREAM_BLUETOOTH_SOCKET", "").strip()
        or DEFAULT_SOCKET_PATH
    )


def classify_loopback_hw(hw: str) -> Optional[str]:
    """Return ``"playback"``/``"capture"`` for an ASBT loopback hw string, else None.

    Matches on the card id substring rather than full-string equality so
    minor formatting differences in how ALSA renders the hint name (case,
    subdevice suffix) don't silently defeat the relabel hook.
    """
    upper = (hw or "").upper()
    if f"CARD={BLUETOOTH_CARD_ID}" not in upper:
        return None
    if "DEV=0" in upper:
        return "playback"
    if "DEV=1" in upper:
        return "capture"
    return None


def is_loopback_playback(hw: str) -> bool:
    """True when ``hw`` is the ASBT loopback's PLAYBACK side.

    Thin wrapper around ``classify_loopback_hw`` for the two call sites that
    only care about the playback classification (the Setup page's synthetic
    "(not currently detected)" option builder, and the settings validator's
    capture_device guard) -- both need "is this the internal device the pump
    feeds, which must never be selectable/settable as a capture device" and
    neither needs the full playback/capture/None tri-state.
    """
    return classify_loopback_hw(hw) == "playback"


class BluetoothClient:
    """Thin wrapper around the autostream_bluetooth Unix domain socket.

    Unlike ``MonitorClient``, there is no persistent connection to manage:
    every public method opens a short-lived socket, sends one JSON command,
    reads one JSON reply, and closes.  This matches the daemon's "one JSON
    request per connection" wire contract and keeps failure handling trivial
    -- a dead/absent daemon simply yields ``None`` from every call.
    """

    DEFAULT_SOCKET_PATH = DEFAULT_SOCKET_PATH
    TIMEOUT = 2.0  # seconds; every call is bounded so a dead daemon can't hang callers

    def __init__(self, socket_path: Optional[str] = None) -> None:
        self._socket_path = socket_path or get_bluetooth_socket_path()

    # ── Low-level request/reply ─────────────────────────────────────────────

    def _request(self, cmd: dict) -> Optional[dict]:
        """Send one JSON command; return the parsed reply dict, or None on any failure."""
        sock: Optional[socket.socket] = None
        cmd_name = cmd.get("cmd")
        try:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.settimeout(self.TIMEOUT)
            sock.connect(self._socket_path)
            sock.sendall((json.dumps(cmd) + "\n").encode("utf-8"))

            buf = b""
            while b"\n" not in buf:
                chunk = sock.recv(4096)
                if not chunk:
                    logger.debug(
                        "BluetoothClient: command %r got EOF with no reply", cmd_name,
                    )
                    return None
                buf += chunk

            line = buf.split(b"\n", 1)[0]
            parsed = json.loads(line)
            if not isinstance(parsed, dict):
                logger.warning(
                    "BluetoothClient: command %r returned non-object response", cmd_name,
                )
                return None
            return parsed
        except socket.timeout:
            logger.debug("BluetoothClient: command %r timed out", cmd_name)
            return None
        except OSError as e:
            # Includes "no such file" (daemon/socket absent) -- expected and
            # quiet whenever the Bluetooth service isn't running.
            logger.debug("BluetoothClient: command %r failed: %s", cmd_name, e)
            return None
        except (json.JSONDecodeError, ValueError) as e:
            logger.warning("BluetoothClient: command %r bad JSON reply: %s", cmd_name, e)
            return None
        finally:
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass

    # ── Commands ─────────────────────────────────────────────────────────

    def status(self) -> Optional[dict]:
        return self._request({"cmd": "status"})

    def scan_start(self) -> Optional[dict]:
        return self._request({"cmd": "scan_start"})

    def scan_stop(self) -> Optional[dict]:
        return self._request({"cmd": "scan_stop"})

    def scan_results(self) -> Optional[dict]:
        return self._request({"cmd": "scan_results"})

    def pair(self, mac: str) -> Optional[dict]:
        return self._request({"cmd": "pair", "mac": mac})

    def pair_status(self) -> Optional[dict]:
        return self._request({"cmd": "pair_status"})

    def forget(self) -> Optional[dict]:
        return self._request({"cmd": "forget"})

    def configure(self, buffer_ms: int) -> Optional[dict]:
        return self._request({"cmd": "configure", "buffer_ms": buffer_ms})
