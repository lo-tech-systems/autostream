"""dial_info.py — the idle screen's read-only info page: what the dial's own
network and disk state look like right now.

This module has NO hardware imports and NO dependency on Pillow, the
compositor, or dial_display's own state machinery — it is a pure data
gatherer, called from a short-lived worker thread the display manager starts
each time the info page opens (see dial_display.DialDisplay.open_info()/
_gather_info()). Its only entry point, gather_dial_info(), NEVER RAISES:
every source is read defensively and any failure degrades that one field to
"-", never the whole page. It is bounded, too — at most three subprocesses
are ever spawned by one call, each capped at _CMD_TIMEOUT_S, so a hung
network tool can never leave the gather thread running indefinitely.

Seven fields, in display order: the dial's own name and firmware version
(passed in by the caller — see dial_main.py's wiring), its IPv4 address, the
Wi-Fi network it is joined to — or, while it is not joined, the network it
is configured for — and a coarse signal category (Disconnected while not
joined), the free space on its root filesystem, and the SD card's remaining
health (passed in by the caller, see dial_sdhealth.info_value()).

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

import json
import os
import re
import socket
import subprocess

INFO_LABELS = ("Dial name", "Firmware", "IPv4", "WiFi", "Signal", "Disk free", "SD health")

SIGNAL_WEAK = "Weak"
SIGNAL_NORMAL = "Normal"
SIGNAL_STRONG = "Strong"
# The Signal field while the dial is not joined to any network: an explicit
# word rather than the "-" every failed probe also shows.
SIGNAL_DISCONNECTED = "Disconnected"

# The configured network: the profile the Wi-Fi watcher commits, by
# connection name and uuid (never an SSID directly), with the older
# name-only file as a fallback. Both are root-written, world-readable.
NETWORK_STATE_PATH = "/etc/autostream-network.json"
LEGACY_CONNECTION_NAME_PATH = "/opt/autostream/ssid"

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


def current_ipv4() -> str:
    """The dial's own IPv4 address, or "" when it has none."""
    return _ipv4() or ""


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


def wifi_status() -> "tuple[str, str]":
    """(ssid, category) for the JOINED network, or (_BLANK, _BLANK) when
    every source fails or nothing is joined. Also the network poller's
    signal source (dial_network.py), so the idle icon and this page always
    grade the link with the same categories."""
    via_nmcli = _wifi_status_nmcli()
    if via_nmcli is not None:
        return via_nmcli
    dbm = _wireless_dbm()
    if dbm is None:
        return (_BLANK, _BLANK)
    ssid = _iwgetid_ssid() or _BLANK
    return (ssid, signal_category_from_dbm(dbm))


_wifi_status = wifi_status  # name kept for existing callers and tests


def _configured_connection() -> "str | None":
    """The committed Wi-Fi profile's uuid (preferred) or name, from the
    network state file, else the legacy name-only file; None when the dial
    has no configured network or neither file is readable. Pure file
    reads, no subprocess."""
    try:
        with open(NETWORK_STATE_PATH, encoding="utf-8") as handle:
            data = json.load(handle)
        if isinstance(data, dict):
            for key in ("connection_uuid", "connection_name"):
                value = data.get(key)
                if isinstance(value, str) and value.strip():
                    return value.strip()
    except (OSError, ValueError):
        pass
    try:
        with open(LEGACY_CONNECTION_NAME_PATH, encoding="utf-8") as handle:
            name = handle.read().strip()
        return name or None
    except OSError:
        return None


def configured_ssid() -> "str | None":
    """The SSID of the configured network profile, whether or not it is
    currently joined: one bounded nmcli read of the profile's own ssid
    setting. None when nothing is configured or nmcli cannot answer."""
    key = _configured_connection()
    if key is None:
        return None
    result = _run(["nmcli", "-g", "802-11-wireless.ssid", "connection", "show", key])
    if result is None or result.returncode != 0:
        return None
    ssid = result.stdout.strip()
    return ssid or None


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


def gather_dial_info(name: str, version: str, network=None, sd_health=None, uuid: str = "") -> "tuple[tuple[str, str], ...]":
    """(label, value) pairs in display order — the info page's own content,
    gathered fresh on every open. Every source is guarded separately (a
    single bad source degrades only its own field to "-"), and the whole
    function is guarded again besides: a wholly broken environment still
    returns seven "-" rows rather than raising into the caller's worker
    thread. Bounded: at most three subprocesses, each capped at
    _CMD_TIMEOUT_S (see _ipv4()/wifi_status()/configured_ssid()).

    *network* is the network poller's latest view (dial_network.latest(),
    or None when unavailable): its link verdict decides the WiFi/Signal
    rows while the dial is offline. The rows show the JOINED network and
    its category while joined; while not joined (the watcher says the link
    is down, or the dial's own probes find no association) they show the
    CONFIGURED network's SSID and "Disconnected", so a dial that has lost
    its network still names the network it is trying to reach. Probes that
    fail outright with no watcher verdict keep the "-" pair: unknown is not
    the same as disconnected.

    *sd_health* is the already formatted SD health value (a plain string,
    or None for "-"); the caller formats it so this module keeps no
    dependency on the reader.

    *uuid* is the dial's own identifier: the Dial name row shows it while
    the dial has no name, the same string the dial advertises as its name
    and the appliance lists it by."""
    try:
        try:
            ipv4 = _ipv4() or _BLANK
        except Exception:
            ipv4 = _BLANK
        try:
            wifi = _wifi_rows(network)
        except Exception:
            wifi = (_BLANK, _BLANK)
        try:
            disk = _disk_free() or _BLANK
        except Exception:
            disk = _BLANK
        return (
            (INFO_LABELS[0], (name or "").strip() or (uuid or "").strip() or _BLANK),
            (INFO_LABELS[1], version or _BLANK),
            (INFO_LABELS[2], ipv4),
            (INFO_LABELS[3], wifi[0]),
            (INFO_LABELS[4], wifi[1]),
            (INFO_LABELS[5], disk),
            (INFO_LABELS[6], (sd_health or "").strip() or _BLANK),
        )
    except Exception:
        return tuple((label, _BLANK) for label in INFO_LABELS)


def _wifi_rows(network) -> "tuple[str, str]":
    """(WiFi, Signal) values — see gather_dial_info() for the rule. The
    watcher's verdict is read duck-typed (anything with a `link` attribute
    equal to "down"), so this module needs no import from the poller."""
    down = getattr(network, "link", None) == "down"
    try:
        joined = wifi_status()
    except Exception:
        joined = None
    if down or joined == (_BLANK, _BLANK):
        try:
            configured = configured_ssid()
        except Exception:
            configured = None
        return (configured or _BLANK, SIGNAL_DISCONNECTED)
    if joined is None:
        return (_BLANK, _BLANK)
    return joined
