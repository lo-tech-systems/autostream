"""dial_info.py — the idle screen's read-only info page: what the dial's own
network and disk state look like right now.

This module has NO hardware imports and NO dependency on Pillow, the
compositor, or dial_display's own state machinery — it is a pure data
gatherer, called from a short-lived worker thread the display manager starts
each time the info page opens (see dial_display.DialDisplay.open_info()/
_gather_info()). Its only entry point, gather_dial_info(), NEVER RAISES:
every source is read defensively and any failure degrades that one field to
"-", never the whole page. It is bounded, too — at most two subprocesses are
ever spawned by one call, each capped at _CMD_TIMEOUT_S, so a hung network
tool can never leave the gather thread running indefinitely.

Six fields, in display order: the dial's own name and firmware version
(passed in by the caller — see dial_main.py's wiring), its IPv4 address, the
Wi-Fi network it is joined to and a coarse signal category for it, and the
free space on its root filesystem.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

import os
import re
import socket
import subprocess

INFO_LABELS = ("Dial name", "Firmware", "IPv4", "WiFi", "Signal", "Disk free")

SIGNAL_WEAK = "Weak"
SIGNAL_NORMAL = "Normal"
SIGNAL_STRONG = "Strong"

# NetworkManager reports Wi-Fi signal as a 0-100 percent; these are the
# categorisation thresholds for it (see signal_category_from_percent()).
SIGNAL_PERCENT_NORMAL_MIN = 35
SIGNAL_PERCENT_STRONG_MIN = 65

# /proc/net/wireless's own dBm level, used only when nmcli is unavailable
# (see signal_category_from_dbm()).
SIGNAL_DBM_NORMAL_MIN = -75
SIGNAL_DBM_STRONG_MIN = -60

# Every subprocess call this module makes is bounded by this timeout — a
# hung network tool must never leave the gather thread running forever.
_CMD_TIMEOUT_S = 2.0

_BLANK = "-"


def signal_category_from_percent(percent: int) -> str:
    """NetworkManager's own 0-100 signal percent -> a coarse category. Pure."""
    if percent >= SIGNAL_PERCENT_STRONG_MIN:
        return SIGNAL_STRONG
    if percent >= SIGNAL_PERCENT_NORMAL_MIN:
        return SIGNAL_NORMAL
    return SIGNAL_WEAK


def signal_category_from_dbm(dbm: float) -> str:
    """/proc/net/wireless's own dBm level -> a coarse category. Pure."""
    if dbm >= SIGNAL_DBM_STRONG_MIN:
        return SIGNAL_STRONG
    if dbm >= SIGNAL_DBM_NORMAL_MIN:
        return SIGNAL_NORMAL
    return SIGNAL_WEAK


def _run(argv: list) -> "subprocess.CompletedProcess | None":
    """Run *argv*, capturing text output, bounded by _CMD_TIMEOUT_S. None on
    any failure (missing binary, timeout, or any other OSError) — every
    caller here treats None exactly like "this source has nothing to say"."""
    try:
        return subprocess.run(
            argv, capture_output=True, text=True, timeout=_CMD_TIMEOUT_S, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None


def _ipv4_via_socket() -> "str | None":
    """A UDP socket connect()ed at a non-routable address, then its own
    local endpoint's address — no packet is actually sent (UDP connect just
    picks a route), so this needs only a default route to exist, not real
    connectivity, and spawns no subprocess."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("10.255.255.255", 1))
            return sock.getsockname()[0]
    except OSError:
        return None


_IP_ADDR_RE = re.compile(r"inet (\d+\.\d+\.\d+\.\d+)/")


def _ipv4_via_ip_command() -> "str | None":
    """Fallback when the socket trick fails (no default route configured,
    an unusual network namespace, ...): parse the first global-scope IPv4
    address `ip` reports."""
    result = _run(["ip", "-4", "-o", "addr", "show", "scope", "global"])
    if result is None or result.returncode != 0:
        return None
    match = _IP_ADDR_RE.search(result.stdout)
    return match.group(1) if match else None


def _ipv4() -> "str | None":
    return _ipv4_via_socket() or _ipv4_via_ip_command()


def _nmcli_split(line: str) -> list:
    """Split one nmcli -t line on unescaped colons, unescaping `\\:`/`\\\\`
    as it goes — nmcli's terse output escapes a literal colon or backslash
    inside a field with a leading backslash, so a plain str.split(":") would
    misparse an SSID containing one."""
    fields = []
    current = []
    i = 0
    while i < len(line):
        ch = line[i]
        if ch == "\\" and i + 1 < len(line):
            current.append(line[i + 1])
            i += 2
            continue
        if ch == ":":
            fields.append("".join(current))
            current = []
            i += 1
            continue
        current.append(ch)
        i += 1
    fields.append("".join(current))
    return fields


def _wifi_status_nmcli() -> "tuple[str, str] | None":
    """(ssid, category) from the active row of `nmcli ... dev wifi list`, or
    None when nmcli is unavailable, fails, or reports no active connection —
    the caller falls back to /proc/net/wireless either way."""
    result = _run(["nmcli", "-t", "-f", "ACTIVE,SSID,SIGNAL", "dev", "wifi", "list", "--rescan", "no"])
    if result is None or result.returncode != 0:
        return None
    for line in result.stdout.splitlines():
        fields = _nmcli_split(line)
        if len(fields) < 3:
            continue
        active, ssid, signal = fields[0], fields[1], fields[2]
        if active != "yes":
            continue
        try:
            percent = int(signal)
        except ValueError:
            continue
        return (ssid or _BLANK, signal_category_from_percent(percent))
    return None


def _wireless_dbm() -> "float | None":
    """The first non-header data line of /proc/net/wireless, fourth
    whitespace-separated field (the signal level, in dBm on every real
    driver). A positive value is a raw link-quality unit some drivers report
    instead of dBm — indistinguishable from a genuine reading here, so it is
    treated as unknown rather than guessed at."""
    try:
        with open("/proc/net/wireless", encoding="utf-8") as handle:
            lines = handle.readlines()
    except OSError:
        return None
    for line in lines[2:]:
        parts = line.split()
        if len(parts) < 4:
            continue
        try:
            level = float(parts[3])
        except ValueError:
            continue
        if level > 0:
            continue
        return level
    return None


def _iwgetid_ssid() -> "str | None":
    result = _run(["iwgetid", "-r"])
    if result is None or result.returncode != 0:
        return None
    ssid = result.stdout.strip()
    return ssid or None


def _wifi_status() -> "tuple[str, str]":
    """(ssid, category), or (_BLANK, _BLANK) when every source fails."""
    via_nmcli = _wifi_status_nmcli()
    if via_nmcli is not None:
        return via_nmcli
    dbm = _wireless_dbm()
    if dbm is None:
        return (_BLANK, _BLANK)
    ssid = _iwgetid_ssid() or _BLANK
    return (ssid, signal_category_from_dbm(dbm))


def _disk_free() -> "str | None":
    """Free space on the root filesystem, formatted "14.2 GB" above 1 GB,
    else "512 MB"."""
    try:
        stat = os.statvfs("/")
    except OSError:
        return None
    free_bytes = stat.f_bavail * stat.f_frsize
    gb = free_bytes / (1024 ** 3)
    if gb > 1:
        return f"{gb:.1f} GB"
    mb = free_bytes / (1024 ** 2)
    return f"{int(mb)} MB"


def gather_dial_info(name: str, version: str) -> "tuple[tuple[str, str], ...]":
    """(label, value) pairs in display order — the info page's own content,
    gathered fresh on every open. Every source is guarded separately (a
    single bad source degrades only its own field to "-"), and the whole
    function is guarded again besides: a wholly broken environment still
    returns six "-" rows rather than raising into the caller's worker
    thread. Bounded: at most two subprocesses, each capped at
    _CMD_TIMEOUT_S (see _ipv4()/_wifi_status())."""
    try:
        try:
            ipv4 = _ipv4() or _BLANK
        except Exception:
            ipv4 = _BLANK
        try:
            wifi = _wifi_status()
        except Exception:
            wifi = (_BLANK, _BLANK)
        try:
            disk = _disk_free() or _BLANK
        except Exception:
            disk = _BLANK
        return (
            (INFO_LABELS[0], (name or "").strip() or _BLANK),
            (INFO_LABELS[1], version or _BLANK),
            (INFO_LABELS[2], ipv4),
            (INFO_LABELS[3], wifi[0]),
            (INFO_LABELS[4], wifi[1]),
            (INFO_LABELS[5], disk),
        )
    except Exception:
        return tuple((label, _BLANK) for label in INFO_LABELS)
