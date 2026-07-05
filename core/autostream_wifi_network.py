#!/usr/bin/python3
"""autostream_wifi_network.py

Copyright (c) 2025 Lo-tech Systems Limited. All rights reserved.

Dedicated, root-owned network-facts and bounded-primitive helper for the
Autostream Wi-Fi recovery watcher (``platform/wifi_watcher``).

Responsibility boundary (see the implementation plan, section 2.7):

  * This module owns *facts* and *bounded primitives*:
      - network-state parsing / atomic writing / legacy migration & mirroring;
      - adapter records and discovery, stable identity;
      - ``nmcli`` query and command-construction primitives;
      - route / neighbour inspection;
      - scan parsing and SSID merging.

  * It MUST NOT contain policy, Flask routes, threads, timers, systemd service
    actions, fallback policy, or another state machine.  Those belong to the
    watcher.

Dependencies are restricted to the Python standard library plus
``autostream_sysutils`` (for ``run_cmd``).  Do not add packages to the recovery
dependency set.
"""
from __future__ import annotations

import ipaddress
import json
import logging
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from autostream_sysutils import run_cmd

logger = logging.getLogger(__name__)

# Bound every nmcli query/probe so a wedged NetworkManager cannot hang the
# caller.  These helpers run on the watcher's monitor loop every pass, so an
# unbounded nmcli that never returns would silence health checks, status
# publishing and the reboot ladders (immediate-fix IF-1).  Kept local to this
# module — it must not import the watcher's timeout constants.  A live scan can
# legitimately be slower than a plain query, so it gets a wider bound.
NMCLI_TIMEOUT = 15        # seconds; plain nmcli query/list/show probes
NMCLI_SCAN_TIMEOUT = 30   # seconds; `device wifi rescan` + `device wifi list`
NMCLI_BSSID_SCAN_TIMEOUT = 15  # seconds; per-call bound on BSSID pin/survey scans

# Final compatibility fallback when hardware classification is inconclusive.
BUILTIN_FALLBACK_IFNAME = "wlan0"

_OK_NEIGH_STATES = {"REACHABLE", "STALE", "DELAY", "PROBE", "PERMANENT"}

_RFC1918_NETS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
)
_LINK_LOCAL_NET = ipaddress.ip_network("169.254.0.0/16")
_THIS_HOST_NET = ipaddress.ip_network("0.0.0.0/8")  # "this host on this network" (RFC 1122)


# ---------------------------------------------------------------------------
# Paths (parameterised as module constants so tests can redirect them)
# ---------------------------------------------------------------------------

# Root-owned persistent network state.  Deliberately NOT inside
# /etc/autostream/ (which is writable by the unprivileged autostream account).
NETWORK_STATE_PATH = "/etc/autostream-network.json"

# Legacy compatibility mirror.  Despite its name it holds a NetworkManager
# connection *name*, not an SSID.  Retained for upgrade/downgrade compatibility.
LEGACY_SSID_PATH = "/opt/autostream/ssid"

SCHEMA_VERSION = 1


# ---------------------------------------------------------------------------
# Network state model
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class NetworkState:
    """Resolved, validated configured-network identity.

    ``connection_name`` empty means the appliance is unconfigured.  The state
    never contains credentials.
    """
    connection_name: str = ""
    connection_uuid: str = ""

    @property
    def is_configured(self) -> bool:
        return bool(self.connection_name)


# ---------------------------------------------------------------------------
# nmcli terse-output parsing
# ---------------------------------------------------------------------------

def split_nmcli_terse(line: str, maxsplit: int = -1) -> list[str]:
    r"""Split an ``nmcli -t`` terse line on unescaped ``:`` separators.

    ``nmcli`` escapes literal ``:`` as ``\:`` and literal ``\`` as ``\\`` in
    terse output, so a naive ``line.split(':')`` corrupts SSIDs and connection
    names that legally contain colons or backslashes.  This parser honours
    those escaping rules and unescapes each returned field.

    ``maxsplit`` limits the number of separator splits; when reached the final
    field keeps any remaining (still unescaped) text verbatim.
    """
    fields: list[str] = []
    current: list[str] = []
    i = 0
    n = len(line)
    splits = 0
    while i < n:
        ch = line[i]
        if ch == "\\" and i + 1 < n:
            # Escaped character — keep the next char literally.
            current.append(line[i + 1])
            i += 2
            continue
        if ch == ":" and (maxsplit < 0 or splits < maxsplit):
            fields.append("".join(current))
            current = []
            splits += 1
            i += 1
            continue
        current.append(ch)
        i += 1
    fields.append("".join(current))
    return fields


# ---------------------------------------------------------------------------
# Atomic file primitives
# ---------------------------------------------------------------------------

def _atomic_write(path: str, data: str, mode: int = 0o644) -> None:
    """Atomically write *data* to *path* with *mode*.

    Creates a temp file in the same directory, flushes, fsyncs, sets mode, then
    ``os.replace`` over the destination.
    """
    directory = os.path.dirname(path) or "."
    fd, tmp = tempfile.mkstemp(prefix=".tmp-", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


# ---------------------------------------------------------------------------
# Network-state load / save / migration
# ---------------------------------------------------------------------------

def _read_legacy_connection_name(path: Optional[str] = None) -> str:
    """Return the connection name from the legacy SSID file, or "" if absent/empty."""
    p = path or LEGACY_SSID_PATH
    try:
        if not os.path.isfile(p):
            return ""
        with open(p, "r", encoding="utf-8") as f:
            return f.read().strip()
    except OSError as e:
        logger.warning("Error reading legacy network file %s: %s", p, e)
        return ""


def _parse_network_json(raw: str) -> Optional[NetworkState]:
    """Parse network.json text into a NetworkState, or None if invalid.

    Unknown keys are ignored.  A wrong/missing schema version is treated as
    invalid so the caller falls back to the legacy file rather than guessing.
    """
    try:
        obj = json.loads(raw)
    except (ValueError, TypeError):
        return None
    if not isinstance(obj, dict):
        return None
    if obj.get("schema_version") != SCHEMA_VERSION:
        return None
    name = obj.get("connection_name", "")
    uuid = obj.get("connection_uuid", "")
    if not isinstance(name, str) or not isinstance(uuid, str):
        return None
    return NetworkState(connection_name=name.strip(), connection_uuid=uuid.strip())


def load_network_state(
    state_path: Optional[str] = None,
    legacy_path: Optional[str] = None,
) -> NetworkState:
    """Resolve the configured network state.

    Resolution order (plan section 3.2):
      1. valid non-empty network.json;
      2. non-empty legacy /opt/autostream/ssid;
      3. unconfigured.

    Invalid/unreadable JSON is logged and falls back to the legacy file rather
    than declaring the appliance unconfigured.
    """
    sp = state_path or NETWORK_STATE_PATH
    lp = legacy_path or LEGACY_SSID_PATH

    if os.path.isfile(sp):
        raw: Optional[str]
        try:
            with open(sp, "r", encoding="utf-8") as f:
                raw = f.read()
        except OSError as e:
            logger.warning("Could not read %s: %s; falling back to legacy file", sp, e)
            raw = None
        if raw is not None:
            parsed = _parse_network_json(raw)
            if parsed is None:
                logger.warning(
                    "Invalid %s; ignoring and falling back to legacy file", sp
                )
            elif parsed.is_configured:
                return parsed
            # An empty-but-valid network.json still means we should consult the
            # legacy file before declaring the appliance unconfigured.

    legacy_name = _read_legacy_connection_name(lp)
    if legacy_name:
        return NetworkState(connection_name=legacy_name, connection_uuid="")

    return NetworkState()


def save_network_state(
    state: NetworkState,
    state_path: Optional[str] = None,
    legacy_path: Optional[str] = None,
    write_legacy: bool = True,
) -> None:
    """Atomically persist *state* to network.json and (optionally) mirror it.

    The legacy mirror receives only ``connection_name`` plus a trailing newline
    — never JSON — so an older watcher can still read it after an upgrade.
    """
    sp = state_path or NETWORK_STATE_PATH
    lp = legacy_path or LEGACY_SSID_PATH

    payload = {
        "schema_version": SCHEMA_VERSION,
        "connection_name": state.connection_name,
        "connection_uuid": state.connection_uuid,
    }
    _atomic_write(sp, json.dumps(payload, indent=2) + "\n", mode=0o644)

    if write_legacy:
        try:
            _atomic_write(lp, f"{state.connection_name}\n", mode=0o644)
        except OSError as e:
            logger.warning("Could not update legacy mirror %s: %s", lp, e)


def resolve_connection_uuid_for_name(name: str) -> str:
    """Resolve a NetworkManager Wi-Fi profile UUID for *name*.

    Returns the UUID only when exactly one matching Wi-Fi profile exists;
    otherwise returns "" and lets the caller log a warning rather than guessing.
    """
    if not name:
        return ""
    r = run_cmd(["nmcli", "-t", "-f", "NAME,UUID,TYPE", "connection", "show"],
                timeout=NMCLI_TIMEOUT)
    if r.returncode != 0:
        return ""
    matches: list[str] = []
    for line in r.stdout.splitlines():
        if not line:
            continue
        parts = split_nmcli_terse(line)
        if len(parts) < 3:
            continue
        cname, cuuid, ctype = parts[0], parts[1], parts[2]
        if cname == name and "wireless" in ctype:
            matches.append(cuuid)
    if len(matches) == 1:
        return matches[0]
    return ""


def migrate_legacy_state(
    state_path: Optional[str] = None,
    legacy_path: Optional[str] = None,
    resolve_uuid: bool = True,
) -> Optional[NetworkState]:
    """Import legacy /opt/autostream/ssid into network.json when needed.

    Performs migration only when network.json is missing/invalid/unconfigured
    AND the legacy file holds a non-empty name.  The legacy file is left
    unchanged (other than being re-mirrored with the same name).  Returns the
    migrated NetworkState, or None when no migration was required.
    """
    sp = state_path or NETWORK_STATE_PATH
    lp = legacy_path or LEGACY_SSID_PATH

    # If network.json already carries a configured name, nothing to migrate.
    if os.path.isfile(sp):
        try:
            with open(sp, "r", encoding="utf-8") as f:
                parsed = _parse_network_json(f.read())
        except OSError:
            parsed = None
        if parsed is not None and parsed.is_configured:
            return None

    legacy_name = _read_legacy_connection_name(lp)
    if not legacy_name:
        return None

    uuid = ""
    if resolve_uuid:
        uuid = resolve_connection_uuid_for_name(legacy_name)
        if not uuid:
            logger.warning(
                "Legacy network '%s' migrated without a resolved UUID "
                "(no profile or multiple matching profiles)",
                legacy_name,
            )

    migrated = NetworkState(connection_name=legacy_name, connection_uuid=uuid)
    save_network_state(migrated, state_path=sp, legacy_path=lp, write_legacy=True)
    logger.info("Migrated legacy network state for connection '%s'", legacy_name)
    return migrated


# ===========================================================================
# Adapter discovery and identity (WP2)
# ===========================================================================

@dataclass(frozen=True)
class WifiAdapter:
    """Immutable record of a detected Wi-Fi adapter.

    ``permanent_mac`` is the stable identity used for deterministic ordering;
    it is normalised lowercase colon-separated text, or "" when no usable MAC
    could be determined.
    """
    ifname: str
    permanent_mac: str
    current_mac: str
    is_builtin: bool
    is_usb: bool
    managed: bool
    state: str
    description: str

    @property
    def kind(self) -> str:
        return "usb" if self.is_usb else "builtin"

    @property
    def stable_id(self) -> str:
        """Identity preferred for ordering: permanent MAC, else ifname."""
        return self.permanent_mac or self.ifname


_ZERO_MACS = {"", "00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"}


def normalise_mac(mac: Optional[str]) -> str:
    """Return a lowercase colon-separated MAC, or "" if empty/zero/malformed."""
    if not mac:
        return ""
    m = mac.strip().lower().replace("-", ":")
    parts = m.split(":")
    if len(parts) != 6:
        return ""
    try:
        for p in parts:
            if len(p) == 0 or len(p) > 2:
                return ""
            int(p, 16)
    except ValueError:
        return ""
    norm = ":".join(p.zfill(2) for p in parts)
    if norm in _ZERO_MACS:
        return ""
    return norm


def _sys_path_is_usb(ifname: str, sys_root: str = "/sys/class/net") -> bool:
    """True when the interface's device path is USB-backed."""
    try:
        link = os.path.realpath(os.path.join(sys_root, ifname))
    except OSError:
        return False
    # USB-attached netdevs have 'usb' in their resolved device path, e.g.
    # /sys/devices/platform/.../usb1/1-1/1-1:1.0/net/wlan1
    return "/usb" in link or "/usb" in link.replace("\\", "/")


def _sys_read_mac(ifname: str, sys_root: str = "/sys/class/net") -> str:
    try:
        with open(os.path.join(sys_root, ifname, "address"), "r", encoding="utf-8") as f:
            return normalise_mac(f.read())
    except OSError:
        return ""


def _nmcli_wifi_devices() -> list[dict]:
    """Return one dict per NetworkManager-reported Wi-Fi device.

    Keys: ifname, state, managed (bool), conn.
    """
    r = run_cmd([
        "nmcli", "-t", "-f", "DEVICE,TYPE,STATE,CONNECTION", "device", "status",
    ], timeout=NMCLI_TIMEOUT)
    devs: list[dict] = []
    if r.returncode != 0:
        return devs
    for line in r.stdout.splitlines():
        if not line:
            continue
        parts = split_nmcli_terse(line, maxsplit=3)
        if len(parts) != 4:
            continue
        device, dev_type, state, conn = parts
        if dev_type != "wifi":
            continue
        devs.append({
            "ifname": device,
            "state": state,
            "managed": state not in ("unmanaged", "unavailable"),
            "conn": conn,
        })
    return devs


def _nmcli_device_detail(ifname: str) -> dict:
    """Return GENERAL.HWADDR / permanent address / product description for a device."""
    base_fields = [
        "GENERAL.HWADDR",
        "GENERAL.STATE",
        "GENERAL.PRODUCT",
        "GENERAL.VENDOR",
    ]
    out: dict[str, str] = {}
    r = run_cmd(["nmcli", "-t", "-f", ",".join(base_fields), "device", "show", ifname],
                timeout=NMCLI_TIMEOUT)
    if r.returncode == 0:
        for line in r.stdout.splitlines():
            if not line:
                continue
            parts = split_nmcli_terse(line, maxsplit=1)
            if len(parts) == 2:
                out[parts[0]] = parts[1]

    # WIFI-PROPERTIES.PERM-HW-ADDRESS is absent from older NM builds; probe
    # silently so a missing field does not produce repeated log noise.
    r2 = run_cmd(
        ["nmcli", "-t", "-f", "WIFI-PROPERTIES.PERM-HW-ADDRESS",
         "device", "show", ifname],
        warn_on_failure=False,
        timeout=NMCLI_TIMEOUT,
    )
    if r2.returncode == 0:
        for line in r2.stdout.splitlines():
            if not line:
                continue
            parts = split_nmcli_terse(line, maxsplit=1)
            if len(parts) == 2:
                out[parts[0]] = parts[1]
    return out


def _is_supported_builtin(ifname: str, is_usb: bool, managed: bool) -> bool:
    """A managed, non-USB Wi-Fi interface is treated as the built-in radio."""
    return managed and not is_usb


def discover_adapters(sys_root: str = "/sys/class/net") -> list[WifiAdapter]:
    """Enumerate managed/available Wi-Fi adapters via NetworkManager + sysfs.

    NetworkManager is the source of the device list; ``/sys/class/net`` is used
    only to determine USB backing and to provide a MAC fallback.
    """
    adapters: list[WifiAdapter] = []
    for dev in _nmcli_wifi_devices():
        ifname = dev["ifname"]
        managed = dev["managed"]
        detail = _nmcli_device_detail(ifname)

        perm = normalise_mac(
            detail.get("WIFI-PROPERTIES.PERM-HW-ADDRESS")
            or detail.get("GENERAL.HWADDR")
        )
        if not perm:
            perm = _sys_read_mac(ifname, sys_root)
        current = normalise_mac(detail.get("GENERAL.HWADDR")) or _sys_read_mac(ifname, sys_root)

        is_usb = _sys_path_is_usb(ifname, sys_root)
        is_builtin = _is_supported_builtin(ifname, is_usb, managed)

        product = (detail.get("GENERAL.PRODUCT") or "").strip()
        vendor = (detail.get("GENERAL.VENDOR") or "").strip()
        description = " ".join(p for p in (vendor, product) if p) or ifname

        adapters.append(WifiAdapter(
            ifname=ifname,
            permanent_mac=perm,
            current_mac=current,
            is_builtin=is_builtin,
            is_usb=is_usb,
            managed=managed,
            state=dev["state"],
            description=description,
        ))
    return adapters


def resolve_builtin(adapters: list[WifiAdapter]) -> Optional[WifiAdapter]:
    """Return the built-in (recovery) adapter, or None if none can be identified.

    Prefers a classified built-in; falls back to a non-USB adapter literally
    named ``wlan0`` when classification is inconclusive.  A USB adapter named
    ``wlan0`` is never returned as the built-in to preserve the recovery
    guarantee (a USB adapter must never become the only recovery path).
    """
    builtins = [a for a in adapters if a.is_builtin]
    if builtins:
        # Deterministic if (unexpectedly) more than one.
        return sorted(builtins, key=lambda a: a.stable_id)[0]
    for a in adapters:
        if a.ifname == BUILTIN_FALLBACK_IFNAME and not a.is_usb:
            return a
    return None


def usb_candidates(adapters: list[WifiAdapter]) -> list[WifiAdapter]:
    """Managed USB adapters sorted deterministically by permanent MAC."""
    usb = [a for a in adapters if a.is_usb and a.managed]
    return sorted(usb, key=lambda a: a.stable_id)


def client_candidate_order(adapters: list[WifiAdapter]) -> list[WifiAdapter]:
    """Automatic client order: USB adapters (by permanent MAC) then built-in."""
    order = usb_candidates(adapters)
    builtin = resolve_builtin(adapters)
    if builtin is not None and builtin not in order:
        order.append(builtin)
    return order


def find_adapter_by_ifname(
    adapters: list[WifiAdapter], ifname: str
) -> Optional[WifiAdapter]:
    for a in adapters:
        if a.ifname == ifname:
            return a
    return None


def find_adapter_by_mac(
    adapters: list[WifiAdapter], mac: str
) -> Optional[WifiAdapter]:
    norm = normalise_mac(mac)
    if not norm:
        return None
    for a in adapters:
        if a.permanent_mac == norm:
            return a
    return None


# ===========================================================================
# USB sysfs reset primitives (dead-PHY recovery — WP1)
# ===========================================================================
#
# These are pure, side-effect-isolated facts/primitives.  They resolve sysfs
# paths and perform the bounded sysfs writes that revive a wedged USB Wi-Fi
# adapter; they contain NO recovery policy, timing, or nmcli orchestration.
# The caller (the watcher) decides *when* to reset, waits for the interface to
# reappear, and re-issues nmcli.  All write functions swallow OSError and
# return False rather than raising.  ``sys_root`` and ``bus_root`` are
# parameterised so tests can point at a fake tree.


def list_sysfs_netdevs(sys_root: str = "/sys/class/net") -> list[str]:
    """Return interface names present in sysfs, independent of NetworkManager.

    Entries in ``/sys/class/net`` are per-interface symlinks to device dirs;
    return the names whose joined path resolves to a directory.
    """
    try:
        names = os.listdir(sys_root)
    except OSError:
        return []
    return sorted(
        n for n in names if os.path.isdir(os.path.join(sys_root, n))
    )


def find_sysfs_netdev_by_mac(mac: str, sys_root: str = "/sys/class/net") -> str:
    """Return the sysfs ifname whose address matches *mac*, or "".

    Consults sysfs only, so a NetworkManager-disappeared but sysfs-present
    adapter can still be located by its stable MAC.
    """
    norm = normalise_mac(mac)
    if not norm:
        return ""
    for name in list_sysfs_netdevs(sys_root):
        if _sys_read_mac(name, sys_root) == norm:
            return name
    return ""


def read_link_down(ifname: str, sys_root: str = "/sys/class/net") -> Optional[bool]:
    """True if carrier==0 or operstate in {down,dormant}; None if unreadable.

    The kernel returns ``EINVAL`` when ``carrier`` is read while the interface
    is administratively down, so a missing carrier is tolerated as long as
    ``operstate`` is readable.
    """
    base = os.path.join(sys_root, ifname)
    carrier: Optional[str] = None
    try:
        with open(os.path.join(base, "carrier"), "r", encoding="utf-8") as f:
            carrier = f.read().strip()
    except OSError:
        carrier = None
    operstate: Optional[str] = None
    try:
        with open(os.path.join(base, "operstate"), "r", encoding="utf-8") as f:
            operstate = f.read().strip().lower()
    except OSError:
        operstate = None

    if carrier is None and operstate is None:
        return None
    if carrier == "0":
        return True
    if operstate in ("down", "dormant"):
        return True
    return False


def read_operstate(ifname: str, sys_root: str = "/sys/class/net") -> str:
    """Return the sysfs operstate string (lowercase), or "" if unreadable."""
    try:
        with open(os.path.join(sys_root, ifname, "operstate"), "r", encoding="utf-8") as f:
            return f.read().strip().lower()
    except OSError:
        return ""


def usb_sysfs_paths(ifname: str, sys_root: str = "/sys/class/net") -> Optional[dict]:
    """Resolve {interface_id, driver, usb_device_path} for a USB-backed netdev.

    interface_id    -> basename(realpath(.../<ifname>/device))         e.g. "1-1.5:1.0"
    driver          -> basename(realpath(.../<ifname>/device/driver))  e.g. "rtl8xxxu"
    usb_device_path -> dirname(realpath(.../<ifname>/device))          e.g. ".../1-1.5"

    Returns None when the device is not USB-backed or paths cannot be resolved.
    """
    device = os.path.join(sys_root, ifname, "device")
    if not os.path.exists(device):
        return None
    dev_real = os.path.realpath(device)
    if "/usb" not in dev_real.replace("\\", "/"):
        return None
    interface_id = os.path.basename(dev_real)
    usb_device_path = os.path.dirname(dev_real)

    driver_link = os.path.join(device, "driver")
    if not os.path.exists(driver_link):
        return None
    driver = os.path.basename(os.path.realpath(driver_link))

    if not interface_id or not driver or not usb_device_path:
        return None
    return {
        "interface_id": interface_id,
        "driver": driver,
        "usb_device_path": usb_device_path,
    }


def reset_usb_adapter_rebind(
    ifname: str,
    *,
    sys_root: str = "/sys/class/net",
    bus_root: str = "/sys/bus/usb",
) -> bool:
    """Method A: write interface_id to drivers/<drv>/unbind then /bind.

    Resolves the interface id *before* unbinding (the netdev vanishes during
    the rebind).  Returns False without raising on any failure.
    """
    paths = usb_sysfs_paths(ifname, sys_root=sys_root)
    if not paths:
        logger.warning(
            "USB rebind reset: cannot resolve sysfs paths for %s", ifname
        )
        return False
    interface_id = paths["interface_id"]
    driver_dir = os.path.join(bus_root, "drivers", paths["driver"])
    try:
        Path(os.path.join(driver_dir, "unbind")).write_text(interface_id)
        Path(os.path.join(driver_dir, "bind")).write_text(interface_id)
    except OSError as e:
        logger.warning(
            "USB rebind reset failed for %s (%s): %s", ifname, interface_id, e
        )
        return False
    return True


def reset_usb_adapter_reenumerate(
    ifname: str,
    *,
    sys_root: str = "/sys/class/net",
    bus_root: str = "/sys/bus/usb",
) -> bool:
    """Method B: write '0' then '1' to <usb_device_path>/authorized.

    Triggers a full USB re-enumeration of the device.  Returns False without
    raising on any failure.  ``bus_root`` is accepted for signature parity with
    Method A; the ``authorized`` node lives under the resolved device path.
    """
    paths = usb_sysfs_paths(ifname, sys_root=sys_root)
    if not paths:
        logger.warning(
            "USB re-enumerate reset: cannot resolve sysfs paths for %s", ifname
        )
        return False
    authorized = os.path.join(paths["usb_device_path"], "authorized")
    try:
        Path(authorized).write_text("0")
        Path(authorized).write_text("1")
    except OSError as e:
        logger.warning("USB re-enumerate reset failed for %s: %s", ifname, e)
        return False
    return True


# ===========================================================================
# Interface-aware health and routing primitives (WP2)
# ===========================================================================

def _is_rfc1918_ipv4(ip: ipaddress.IPv4Address) -> bool:
    return any(ip in n for n in _RFC1918_NETS)


def is_usable_unicast_ipv4(value) -> bool:
    """True for usable non-link-local unicast IPv4 addresses.

    This is intentionally broader than the WiFi local-health policy: ethernet
    may be directly connected or publicly routed, so RFC1918 is not required.
    """
    try:
        ip = ipaddress.ip_interface(value).ip
    except (TypeError, ValueError):
        try:
            ip = ipaddress.ip_address(value)
        except (TypeError, ValueError):
            return False
    if not isinstance(ip, ipaddress.IPv4Address):
        return False
    return not (
        ip in _THIS_HOST_NET
        or ip.is_unspecified
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
    )


def _nmcli_dev_show_fields(ifname: str, fields: list[str]) -> dict[str, list[str]]:
    """Return selected ``nmcli -t ... dev show <ifname>`` fields.

    Maps each base field name to a list of values (nmcli can emit indexed keys
    like IP4.ADDRESS[1], IP4.ADDRESS[2]).
    """
    r = run_cmd(["nmcli", "-t", "-f", ",".join(fields), "device", "show", ifname],
                timeout=NMCLI_TIMEOUT)
    if r.returncode != 0:
        return {}
    out: dict[str, list[str]] = {}
    for line in r.stdout.splitlines():
        if ":" not in line:
            continue
        parts = split_nmcli_terse(line, maxsplit=1)
        if len(parts) != 2:
            continue
        k, v = parts[0].strip(), parts[1].strip()
        if not k:
            continue
        base = k.split("[", 1)[0]
        out.setdefault(base, []).append(v)
    return out


def is_local_ipv4_ready(ifname: str) -> bool:
    """True when *ifname* is NM-connected and has a non-link-local RFC1918 IPv4."""
    try:
        info = _nmcli_dev_show_fields(ifname, ["GENERAL.STATE", "IP4.ADDRESS"])
        if not info:
            return False
        state_vals = info.get("GENERAL.STATE", [])
        if not state_vals:
            return False
        try:
            state_code = int(state_vals[0].split()[0])
        except (ValueError, IndexError):
            state_code = -1
        if state_code != 100:
            return False
        for a in info.get("IP4.ADDRESS", []):
            try:
                ip = ipaddress.ip_interface(a).ip
            except ValueError:
                continue
            if not isinstance(ip, ipaddress.IPv4Address):
                continue
            if ip in _LINK_LOCAL_NET:
                continue
            if _is_rfc1918_ipv4(ip):
                return True
        return False
    except Exception as e:
        logger.warning("Local IPv4 readiness check failed on %s: %s", ifname, e)
        return False


def interface_has_usable_ipv4(ifname: str) -> bool:
    """True when *ifname* has any usable non-link-local IPv4 address."""
    for addr in list_interface_addresses(ifname).get(ifname, []):
        if addr.get("family") != "ipv4":
            continue
        if is_usable_unicast_ipv4(addr.get("address", "")):
            return True
    return False


def _run_ip_json(args: list[str]) -> list[dict]:
    p = run_cmd(["ip", "-j", *args], timeout=2.0)
    if p.returncode != 0:
        raise RuntimeError(
            f"`ip -j {' '.join(args)}` failed: rc={p.returncode}, stderr={p.stderr.strip()}"
        )
    out = p.stdout.strip()
    return json.loads(out) if out else []


def _stateset(state_field) -> set[str]:
    if isinstance(state_field, list):
        return {str(s).upper() for s in state_field}
    if isinstance(state_field, str):
        return {state_field.upper()}
    return set()


def is_gateway_reachable(ifname: str, prime_fn=None) -> bool:
    """Interface-specific kernel gateway reachability.

    Selects a default route whose ``dev`` equals *ifname*, validates that
    route's gateway, and accepts only a neighbour entry for that gateway *on the
    same interface*.  This prevents Ethernet or the other Wi-Fi adapter from
    making a failed adapter appear healthy.
    """
    try:
        routes = _run_ip_json(["route", "show", "default"])
        if not routes:
            return False

        gw = None
        for r in routes:
            if r.get("dev") == ifname and r.get("gateway"):
                gw = r.get("gateway")
                break
        if not gw:
            return False
        try:
            ipaddress.ip_address(gw)
        except ValueError:
            return False

        if prime_fn is not None:
            try:
                prime_fn(gw, ifname)
            except Exception:
                pass

        # "dev <ifname>" filters the output; ip typically omits the "dev" field
        # from each entry because the filter makes it redundant.  Accept entries
        # where "dev" is absent (trust the command filter) or matches ifname;
        # reject entries that explicitly name a different interface.
        neigh = _run_ip_json(["neigh", "show", "to", gw, "dev", ifname])
        for n in neigh:
            dev = n.get("dev")
            if (dev is None or dev == ifname) and (_stateset(n.get("state")) & _OK_NEIGH_STATES):
                return True
        return False
    except Exception as e:
        logger.warning("Interface gateway reachability check failed on %s: %s", ifname, e)
        return False


def get_active_wifi_connection_name(ifname: str) -> str:
    """Active connection profile name on *ifname*, or "" if unknown."""
    r = run_cmd(["nmcli", "-t", "-f", "DEVICE,TYPE,STATE,CONNECTION", "device", "status"],
                timeout=NMCLI_TIMEOUT)
    if r.returncode != 0:
        return ""
    for line in r.stdout.splitlines():
        parts = split_nmcli_terse(line, maxsplit=3)
        if len(parts) != 4:
            continue
        dev, dev_type, state, conn = parts
        if dev == ifname and dev_type == "wifi" and state in ("connected", "activated") and conn:
            return conn
    return ""


def get_active_wifi_ssid(ifname: str = "") -> str:
    """SSID of the active Wi-Fi connection, or "" if unknown.

    When *ifname* is given the search is scoped to that interface; omitting it
    (or passing "") scans all interfaces, which is more reliable when the active
    adapter may differ from the one tracked internally.
    """
    cmd = ["nmcli", "-t", "-f", "IN-USE,SSID", "device", "wifi", "list"]
    if ifname:
        cmd += ["ifname", ifname]
    r = run_cmd(cmd, timeout=NMCLI_SCAN_TIMEOUT)
    if r.returncode != 0:
        return ""
    for line in r.stdout.splitlines():
        parts = split_nmcli_terse(line, maxsplit=1)
        if len(parts) != 2:
            continue
        in_use, ssid = parts
        if in_use.strip() == "*" and ssid:
            return ssid
    return ""


def get_connection_ssid(name_or_uuid: str) -> str:
    """Return the 802-11-wireless.ssid of a saved connection profile, or "".

    Facts-only bounded primitive: used by the recovery-hotspot scan gate to learn
    which SSID to look for.  Returns "" on any failure or for a non-Wi-Fi profile.
    """
    if not name_or_uuid:
        return ""
    r = run_cmd(["nmcli", "-g", "802-11-wireless.ssid", "connection", "show", name_or_uuid],
                timeout=NMCLI_TIMEOUT)
    if r.returncode != 0:
        return ""
    return r.stdout.strip()


def is_wifi_connected(ifname: str) -> bool:
    """True if *ifname* is connected to a non-AP Wi-Fi network."""
    result = run_cmd(["nmcli", "-t", "-f", "DEVICE,TYPE,STATE,CONNECTION", "device", "status"],
                     timeout=NMCLI_TIMEOUT)
    if result.returncode != 0:
        logger.warning("Error while checking WiFi connection state: %s", result.stderr.strip())
        return False
    for line in result.stdout.splitlines():
        if not line:
            continue
        parts = split_nmcli_terse(line, maxsplit=3)
        if len(parts) != 4:
            continue
        device, dev_type, state, conn = parts
        if device != ifname or dev_type != "wifi":
            continue
        if state not in ("connected", "activated") or not conn:
            return False
        mode_result = run_cmd(["nmcli", "-t", "-f", "802-11-wireless.mode", "connection", "show", conn],
                              timeout=NMCLI_TIMEOUT)
        if mode_result.returncode != 0:
            logger.warning("Error checking mode for connection '%s': %s", conn, mode_result.stderr.strip())
            return False
        _, _, mode = mode_result.stdout.strip().partition(":")
        return mode.strip().lower() != "ap"
    return False


# ===========================================================================
# NetworkManager command primitives — explicit interface targeting (WP2)
# ===========================================================================

def activate_connection_cmd(connection_uuid: str, connection_name: str, ifname: str) -> list[str]:
    """Build an explicit ``nmcli connection up`` command targeting *ifname*.

    Prefers ``uuid <...>`` when available; falls back to ``id <name>`` for
    unresolved legacy state.
    """
    if connection_uuid:
        ident = ["uuid", connection_uuid]
    else:
        ident = ["id", connection_name]
    return ["nmcli", "connection", "up", *ident, "ifname", ifname]


def rescan_cmd(ifname: str) -> list[str]:
    return ["nmcli", "device", "wifi", "rescan", "ifname", ifname]


def add_wifi_profile_cmd(con_name: str, ifname: str, ssid: str) -> list[str]:
    return [
        "nmcli", "connection", "add", "type", "wifi",
        "con-name", con_name, "ifname", ifname, "ssid", ssid,
    ]


# Profile settings that would prevent cross-adapter fallback (plan section 5.2).
CROSS_ADAPTER_RESTRICTIONS = (
    "connection.interface-name",
    "802-11-wireless.mac-address",
    "802-11-wireless.bssid",
    "802-11-wireless.band",
    "802-11-wireless.channel",
)


def clear_restrictions_cmd(connection_uuid: str, keys: tuple[str, ...]) -> list[str]:
    """Build an ``nmcli connection modify`` clearing the given restriction keys.

    Each key is set to an empty value, which NetworkManager interprets as the
    default/unset.  SSID and security settings are never touched.
    """
    cmd = ["nmcli", "connection", "modify", "uuid", connection_uuid]
    for k in keys:
        cmd.extend([k, ""])
    return cmd


def bssid_scan_cmd(ifname: str, rescan: bool) -> list[str]:
    return [
        "nmcli", "-t", "-f", "IN-USE,BSSID,SSID,SIGNAL", "device", "wifi", "list",
        "ifname", ifname, "--rescan", "yes" if rescan else "no",
    ]


def parse_bssid_scan_output(stdout: str) -> list[dict]:
    """Parse ``nmcli -t -f IN-USE,BSSID,SSID,SIGNAL device wifi list`` output.

    Rows with an empty SSID/BSSID or an unparsable signal are dropped.
    """
    rows: list[dict] = []
    for line in stdout.splitlines():
        if not line:
            continue
        parts = split_nmcli_terse(line, maxsplit=3)
        if len(parts) != 4:
            continue
        in_use, bssid, ssid, signal = parts
        if not bssid or not ssid:
            continue
        try:
            signal_i = int(signal)
        except ValueError:
            continue
        rows.append({
            "in_use": in_use.strip() == "*",
            "bssid": bssid.upper(),
            "ssid": ssid,
            "signal": signal_i,
        })
    return rows


def set_bssid_cmd(connection_uuid: str, bssid: str) -> list[str]:
    """Build an ``nmcli connection modify`` pinning (or clearing) the profile BSSID."""
    return ["nmcli", "connection", "modify", "uuid", connection_uuid,
            "802-11-wireless.bssid", bssid]


def delete_connection_cmd(connection_uuid: str) -> list[str]:
    return ["nmcli", "connection", "delete", "uuid", connection_uuid]


def get_connection_uuid_by_name_cmd(name: str) -> list[str]:
    return [
        "nmcli", "-g", "connection.uuid",
        "connection", "show", "id", name,
    ]


# ===========================================================================
# Captive-portal scanning and exact-SSID merging (WP3)
# ===========================================================================

def parse_scan_output(stdout: str) -> dict[str, int]:
    """Parse ``nmcli -t -f SSID,SIGNAL device wifi list`` output.

    Returns a map of SSID -> strongest signal seen.  Hidden/empty SSIDs are
    omitted.  Honours nmcli escaping so SSIDs with colons survive.
    """
    strongest: dict[str, int] = {}
    for line in stdout.splitlines():
        if not line:
            continue
        parts = split_nmcli_terse(line, maxsplit=1)
        if len(parts) != 2:
            continue
        ssid = parts[0]
        if not ssid:
            continue
        try:
            signal = int(parts[1])
        except ValueError:
            continue
        if signal > strongest.get(ssid, -1):
            strongest[ssid] = signal
    return strongest


def scan_adapter(adapter: "WifiAdapter") -> Optional[dict[str, int]]:
    """Live-scan a single adapter.

    Returns SSID->signal on success, or None when the scan failed (so the
    caller can mark that adapter's visibility *unknown* for this response).
    """
    # A rescan request is best-effort; the list call returns cached+fresh APs.
    run_cmd(rescan_cmd(adapter.ifname), timeout=NMCLI_SCAN_TIMEOUT)
    r = run_cmd([
        "nmcli", "-t", "-f", "SSID,SIGNAL", "device", "wifi", "list",
        "ifname", adapter.ifname,
    ], timeout=NMCLI_SCAN_TIMEOUT)
    if r.returncode != 0:
        logger.debug("Scan failed on %s: %s", adapter.ifname, r.stderr.strip())
        return None
    return parse_scan_output(r.stdout)


def merge_scans(
    builtin_scan: Optional[dict[str, int]],
    usb_scans: list[dict[str, int]],
    builtin_mac: str = "",
    usb_macs: Optional[list[str]] = None,
) -> list[dict]:
    """Merge per-adapter scan results by exact SSID.

    Each merged record carries:
      ssid, signal (strongest from any adapter), builtin_visible, usb_visible,
      adapter_macs (the MACs that saw it).

    A scan that is None (failed/unavailable) does not contribute visibility for
    that adapter.  Sorted by strongest signal descending.
    """
    usb_macs = usb_macs or []
    merged: dict[str, dict] = {}

    def _add(ssid: str, signal: int, *, builtin: bool, mac: str):
        rec = merged.setdefault(ssid, {
            "ssid": ssid, "signal": -1,
            "builtin_visible": False, "usb_visible": False,
            "adapter_macs": [],
        })
        if signal > rec["signal"]:
            rec["signal"] = signal
        if builtin:
            rec["builtin_visible"] = True
        else:
            rec["usb_visible"] = True
        if mac and mac not in rec["adapter_macs"]:
            rec["adapter_macs"].append(mac)

    if builtin_scan is not None:
        for ssid, sig in builtin_scan.items():
            _add(ssid, sig, builtin=True, mac=builtin_mac)

    for idx, scan in enumerate(usb_scans):
        if scan is None:
            continue
        mac = usb_macs[idx] if idx < len(usb_macs) else ""
        for ssid, sig in scan.items():
            _add(ssid, sig, builtin=False, mac=mac)

    return sorted(merged.values(), key=lambda r: r["signal"], reverse=True)


def connection_target_order(
    ssid: str,
    adapters: list["WifiAdapter"],
    merged: list[dict],
    builtin_scan_known: bool,
) -> list["WifiAdapter"]:
    """Adapter order to try when applying credentials for *ssid* (Section 6.4).

    1. USB adapters that saw the SSID (by permanent MAC);
    2. built-in adapter if it saw the SSID;
    3. other managed USB adapters as best-effort when their visibility is unknown;
    4. built-in as a final best-effort when its visibility is unknown.
    """
    rec = next((r for r in merged if r["ssid"] == ssid), None)
    saw_macs = set(rec["adapter_macs"]) if rec else set()
    builtin_visible = bool(rec and rec["builtin_visible"])

    usb = usb_candidates(adapters)
    builtin = resolve_builtin(adapters)

    order: list[WifiAdapter] = []
    # 1) USB adapters that saw the SSID.
    for a in usb:
        if a.permanent_mac and a.permanent_mac in saw_macs:
            order.append(a)
    # 2) built-in if it saw the SSID.
    if builtin is not None and builtin_visible:
        order.append(builtin)
    # 3) other USB adapters (visibility unknown) as best-effort.
    for a in usb:
        if a not in order:
            order.append(a)
    # 4) built-in as final best-effort when its visibility is unknown.
    if builtin is not None and builtin not in order and not builtin_scan_known:
        order.append(builtin)
    return order


# ===========================================================================
# Candidate-profile transaction primitives (WP3 / Section 6.5)
# ===========================================================================

def generate_candidate_name(rand_hex: Optional[str] = None) -> str:
    """Return a uniquely named candidate profile, e.g. autostream-wifi-<8hex>."""
    import secrets
    suffix = rand_hex or secrets.token_hex(4)
    return f"autostream-wifi-{suffix}"


def configure_candidate_cmds(
    con_name: str, ifname: str, ssid: str, password: str,
) -> tuple[list[list[str]], list[list[str]]]:
    """Build the create+configure command list for a candidate profile.

    Returns ``(cmds, log_cmds)`` where ``log_cmds`` masks the PSK so callers can
    pass the sanitised form to run_cmd's log_cmd argument. The created profile
    uses infrastructure mode, ipv4.method auto, and (for protected networks)
    wpa-psk with the submitted key. Open networks set no security.
    """
    add = add_wifi_profile_cmd(con_name, ifname, ssid)
    modify = [
        "nmcli", "connection", "modify", con_name,
        "802-11-wireless.mode", "infrastructure",
        "ipv4.method", "auto",
        # D-WP1: the watcher owns activation/reconnection; disable NM autoconnect
        # so NM never races the watcher's single-decider path onto a stale radio.
        "connection.autoconnect", "no",
    ]
    cmds = [add, modify]
    log_cmds = [add, modify]
    if password:
        sec = [
            "nmcli", "connection", "modify", con_name,
            "802-11-wireless-security.key-mgmt", "wpa-psk",
            "802-11-wireless-security.psk", password,
        ]
        sec_log = [
            "nmcli", "connection", "modify", con_name,
            "802-11-wireless-security.key-mgmt", "wpa-psk",
            "802-11-wireless-security.psk", "*" * len(password),
        ]
        cmds.append(sec)
        log_cmds.append(sec_log)
    return cmds, log_cmds


def list_wifi_connection_profiles() -> list[tuple[str, str]]:
    """Return ``(uuid, name)`` for every saved 802-11-wireless connection profile.

    Facts-only primitive for the D-WP2 startup migration; the caller filters out
    AP-mode profiles via wifi_profile_mode().  Returns [] on any nmcli failure.
    """
    r = run_cmd(["nmcli", "-t", "-f", "NAME,UUID,TYPE", "connection", "show"],
                timeout=NMCLI_TIMEOUT)
    if r.returncode != 0:
        return []
    out: list[tuple[str, str]] = []
    for line in r.stdout.splitlines():
        if not line:
            continue
        parts = split_nmcli_terse(line, maxsplit=2)
        if len(parts) != 3:
            continue
        name, uuid, ctype = parts
        # nmcli reports the connection type as "802-11-wireless" (terse -f TYPE)
        # on most releases; accept the short "wifi" spelling too for robustness.
        if ctype in ("802-11-wireless", "wifi"):
            out.append((uuid, name))
    return out


def wifi_profile_mode(name_or_uuid: str) -> str:
    """Return the lowercased 802-11-wireless.mode of a profile.

    "ap" for a hotspot profile, "infrastructure" (or "") for a client profile.
    Returns "" on any failure or for a non-Wi-Fi profile.
    """
    if not name_or_uuid:
        return ""
    r = run_cmd(["nmcli", "-t", "-f", "802-11-wireless.mode", "connection", "show", name_or_uuid],
                timeout=NMCLI_TIMEOUT)
    if r.returncode != 0:
        return ""
    _, _, mode = r.stdout.strip().partition(":")
    return mode.strip().lower()


def set_autoconnect_no_cmd(uuid: str, name: str = "") -> list[str]:
    """Build the idempotent 'disable NM autoconnect' modify command for a profile.

    Prefers ``uuid <...>``; falls back to ``id <name>`` for unresolved legacy state.
    """
    ident = ["uuid", uuid] if uuid else ["id", name]
    return ["nmcli", "connection", "modify", *ident, "connection.autoconnect", "no"]


def get_profile_uuid(con_name: str) -> str:
    """Return the UUID of a profile by exact name, or "" if not found/ambiguous."""
    r = run_cmd(["nmcli", "-t", "-f", "NAME,UUID", "connection", "show"],
                timeout=NMCLI_TIMEOUT)
    if r.returncode != 0:
        return ""
    matches = []
    for line in r.stdout.splitlines():
        if not line:
            continue
        parts = split_nmcli_terse(line, maxsplit=1)
        if len(parts) == 2 and parts[0] == con_name:
            matches.append(parts[1])
    return matches[0] if len(matches) == 1 else ""


# ===========================================================================
# Runtime dnsmasq interface binding (WP4 / Section 7.2)
# ===========================================================================

DNSMASQ_IFACE_TOKEN = "__AUTOSTREAM_WIFI_IFACE__"
RUNTIME_DIR = "/run/autostream"


def render_dnsmasq_runtime_config(template_text: str, ifname: str) -> str:
    """Substitute the single interface token in a dnsmasq template.

    Fails (ValueError) if the token is absent or appears more than once, so a
    malformed template cannot silently produce a misconfigured captive portal.
    The interface name itself must be a plain device name (no whitespace / token
    characters) so it cannot inject extra config lines.
    """
    count = template_text.count(DNSMASQ_IFACE_TOKEN)
    if count == 0:
        raise ValueError("dnsmasq template missing interface token")
    if count > 1:
        raise ValueError("dnsmasq template has a duplicated interface token")
    if not ifname or not _is_safe_ifname(ifname):
        raise ValueError(f"unsafe interface name for dnsmasq config: {ifname!r}")
    return template_text.replace(DNSMASQ_IFACE_TOKEN, ifname)


def _is_safe_ifname(ifname: str) -> bool:
    if not ifname or len(ifname) > 64:
        return False
    return all(c.isalnum() or c in "-_." for c in ifname)


def write_dnsmasq_runtime_config(
    template_path: str,
    runtime_path: str,
    ifname: str,
    runtime_dir: Optional[str] = None,
) -> None:
    """Read a dnsmasq template, substitute the validated interface, and write
    the runtime file atomically under the (root-owned) runtime directory.

    The runtime directory is created if needed.  Caller (the watcher) is
    responsible for having already validated that *ifname* is the resolved
    built-in adapter.
    """
    directory = runtime_dir or os.path.dirname(runtime_path) or RUNTIME_DIR
    os.makedirs(directory, exist_ok=True)
    with open(template_path, "r", encoding="utf-8") as f:
        template_text = f.read()
    rendered = render_dnsmasq_runtime_config(template_text, ifname)
    _atomic_write(runtime_path, rendered, mode=0o644)


def remove_dnsmasq_runtime_config(runtime_path: str) -> None:
    """Best-effort removal of the generated runtime config."""
    try:
        os.unlink(runtime_path)
    except OSError:
        pass


# ===========================================================================
# Runtime network-status snapshot (dead-PHY recovery — WP6)
# ===========================================================================
#
# The watcher stores its derived network state in memory and serves it over
# HTTP.  Core keeps the shared schema-version constant and bounded facts only;
# derived meaning remains platform policy in platform/wifi_status.py.

NETWORK_STATUS_SCHEMA_VERSION = 1


def list_interface_addresses(ifname: Optional[str] = None) -> dict:
    """Return per-interface IP addresses via ``ip -j addr show``.

    Maps ``{ifname: [{family, address, prefixlen, scope}, ...]}`` where family
    is "ipv4"/"ipv6".  Returns {} on failure.  Facts only — no policy about
    which address is "primary" or whether the interface is "online".
    """
    args = ["addr", "show"]
    if ifname:
        args += ["dev", ifname]
    try:
        data = _run_ip_json(args)
    except Exception as e:
        logger.debug("`ip -j addr show` failed: %s", e)
        return {}
    out: dict = {}
    for entry in data:
        name = entry.get("ifname")
        if not name:
            continue
        addrs = []
        for a in entry.get("addr_info", []):
            local = a.get("local")
            fam = a.get("family")
            if not local or fam not in ("inet", "inet6"):
                continue
            addrs.append({
                "family": "ipv4" if fam == "inet" else "ipv6",
                "address": local,
                "prefixlen": a.get("prefixlen"),
                "scope": a.get("scope", ""),
            })
        out[name] = addrs
    return out


def _default_gateways_ipv4(ifname: str) -> list[str]:
    """Return valid IPv4 default-route gateways for *ifname*."""
    try:
        routes = _run_ip_json(["route", "show", "default"])
    except Exception:
        return []
    gateways: list[str] = []
    for r in routes:
        if r.get("dev") == ifname and r.get("gateway"):
            gw = r.get("gateway")
            try:
                ip = ipaddress.ip_address(gw)
            except ValueError:
                continue
            if isinstance(ip, ipaddress.IPv4Address):
                gateways.append(gw)
    return gateways


def default_gateway_ipv4(ifname: str) -> str:
    """Return the IPv4 default-route gateway for *ifname*, or "".

    Fact helper for the status snapshot; reachability classification stays in
    the watcher's existing route/neighbour logic (is_gateway_reachable).
    """
    gateways = _default_gateways_ipv4(ifname)
    return gateways[0] if gateways else ""


# same_l3_segment / _single_usable_ipv4_interface were removed with the
# same-subnet Wi-Fi-disconnect policy: the watcher now runs a simple "usable
# wired Ethernet wins" policy regardless of subnet (state-machine refactor,
# Section 2.7), so the helper no longer needs to compare L3 segments.
