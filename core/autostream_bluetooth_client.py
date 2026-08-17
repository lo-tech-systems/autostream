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

Also hosts the small set of constants and helpers that are shared between
the coordinator (relabel hook) and the web UI (routes, settings guard,
About page) so there is a single source of truth for the pinned wire/ALSA
constants:

  - ``BLUETOOTH_CAPTURE_DEVICE`` / ``BLUETOOTH_PLAYBACK_DEVICE`` -- the two
    sides of the ``snd-aloop`` pseudo-device.
  - ``bluetooth_installed()`` / ``bluetooth_services_enabled()`` /
    ``bluetooth_onboard_enabled()`` -- the three independent gates
    controlling the optional Bluetooth-input subsystem: whether the unit is
    installed at all, whether it is enabled/running, and whether the
    onboard radio (as opposed to a USB adapter) is in use.
  - ``classify_loopback_hw()`` / ``bluetooth_capture_label()`` -- the small
    amount of logic the device-list relabel hook needs.
  - ``bluetooth_card_summary()`` / ``bluetooth_paired_row_text()`` /
    ``bluetooth_input_fragment_text()`` -- the single source of truth for
    the Bluetooth card's and input card's presentation strings, shared
    between the Setup page's server render, the status JSON API's ``ui``
    payload, and the JS poll that refreshes the card in place.
"""

from __future__ import annotations

import json
import logging
import os
import socket
import subprocess
from typing import Optional

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

_DEFAULT_UNIT_PATH = "/etc/systemd/system/autostream_bluetooth.service"
_DEFAULT_BOOT_CONFIG_PATH = "/boot/firmware/config.txt"
_DISABLE_BT_OVERLAY = "dtoverlay=disable-bt"

_LABEL_UNPAIRED = "Bluetooth (not paired)"
_LABEL_UNAVAILABLE = "Bluetooth (service unavailable)"


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
    path = (
        config_path
        or os.environ.get("AUTOSTREAM_BOOT_CONFIG_PATH", "").strip()
        or _DEFAULT_BOOT_CONFIG_PATH
    )
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                if line.strip() == _DISABLE_BT_OVERLAY:
                    return False
        return True
    except OSError:
        return False


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


def bluetooth_capture_label(status: Optional[dict]) -> str:
    """Return the Setup-page label for the loopback capture device.

    ``status`` is the cached/live daemon ``status`` reply (or None when the
    service is absent/unreachable).  Exactly the three label strings pinned
    as: "Bluetooth: <name>", "Bluetooth (not paired)",
    "Bluetooth (service unavailable)".
    """
    if not isinstance(status, dict) or status.get("ok") is not True:
        return _LABEL_UNAVAILABLE
    paired = status.get("paired")
    if isinstance(paired, dict):
        name = str(paired.get("name") or "").strip()
        if name:
            return f"Bluetooth: {name}"
    return _LABEL_UNPAIRED


def _format_sample_rate_khz(sample_rate) -> Optional[str]:
    """Render a Hz integer as '44.1 kHz' / '48 kHz' (one decimal only when
    the kHz value is non-integer), or None when *sample_rate* isn't a
    positive number."""
    if not isinstance(sample_rate, (int, float)) or isinstance(sample_rate, bool) or sample_rate <= 0:
        return None
    khz = sample_rate / 1000.0
    if khz == int(khz):
        return f"{int(khz)} kHz"
    return f"{khz:.1f} kHz"


def _codec_rate_suffix(status: Optional[dict]) -> str:
    """' <CODEC> <rate>' (leading space) when *status* carries codec/rate
    fields, else ''. Setup-card-only formatting helper -- never call this
    for home-page-facing text (see module docstring)."""
    if not isinstance(status, dict):
        return ""
    codec = str(status.get("codec") or "").strip()
    rate_text = _format_sample_rate_khz(status.get("sample_rate"))
    parts = [p for p in (codec, rate_text) if p]
    return f" {' '.join(parts)}" if parts else ""


def bluetooth_card_summary(services_enabled: bool, status: Optional[dict]) -> str:
    """Bluetooth card summary line, per the five pinned states.

    ``status`` is the cached/live daemon ``status`` reply (or None when the
    service is absent/unreachable). This is the single source of truth for
    the string -- shared between the Setup page's server render, the status
    JSON API's ``ui`` payload, and (via that payload) the JS poll that
    refreshes the card without a full page reload, so the "paired but link
    down" case can't be computed one way in one place and another way
    elsewhere.

    When streaming and the daemon reports ``codec``/``sample_rate``, the
    connected state appends the negotiated format, e.g.
    "Enabled · Turntable connected - SBC 44.1 kHz". Purely additive: absent
    fields leave the text unchanged from before this existed.
    """
    if not services_enabled:
        return "Disabled"
    if not isinstance(status, dict) or not status.get("adapter_present"):
        return "Enabled · No adapter found"
    paired = status.get("paired")
    if not isinstance(paired, dict) or not str(paired.get("name") or "").strip():
        return "Enabled · Not paired"
    name = str(paired.get("name")).strip()
    if str(status.get("link") or "disconnected") == "connected":
        suffix = _codec_rate_suffix(status)
        format_note = f" -{suffix}" if suffix else ""
        return f"Enabled · {name} connected{format_note}"
    return f"Enabled · {name} (not connected)"


def bluetooth_paired_row_text(status: Optional[dict]) -> str:
    """Card 'Paired' row text: '<name> · Connected/Not Connected', or 'No device paired'.

    When connected and *status* carries ``codec``/``sample_rate``, appends
    the negotiated format, e.g. 'Turntable · Connected - SBC 44.1 kHz'.
    Purely additive: absent fields leave the text unchanged from before this
    existed.
    """
    paired = status.get("paired") if isinstance(status, dict) else None
    if not isinstance(paired, dict) or not str(paired.get("name") or "").strip():
        return "No device paired"
    name = str(paired.get("name")).strip()
    link = str(status.get("link") or "disconnected") if isinstance(status, dict) else "disconnected"
    if link == "connected":
        suffix = _codec_rate_suffix(status)
        format_note = f" -{suffix}" if suffix else ""
        return f"{name} · Connected{format_note}"
    return f"{name} · Not Connected"


def bluetooth_input_fragment_text(status: Optional[dict]) -> str:
    """Input-card Bluetooth fragment: the paired device's name when linked, else 'Not Connected'.

    Used as the middle segment of an input card's 'Bluetooth · <X> · <gain>'
    summary, in place of the ALSA card name and turntable flag a non-Bluetooth
    input would show there.
    """
    link = str(status.get("link") or "disconnected") if isinstance(status, dict) else "disconnected"
    if link != "connected":
        return "Not Connected"
    paired = status.get("paired") if isinstance(status, dict) else None
    name = str(paired.get("name") or "").strip() if isinstance(paired, dict) else ""
    return name or "Connected"


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
