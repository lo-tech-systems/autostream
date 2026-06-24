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
from typing import Optional

from autostream_sysutils import run_cmd

logger = logging.getLogger(__name__)

# Final compatibility fallback when hardware classification is inconclusive.
BUILTIN_FALLBACK_IFNAME = "wlan0"

_OK_NEIGH_STATES = {"REACHABLE", "STALE", "DELAY", "PROBE", "PERMANENT"}

_RFC1918_NETS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
)
_LINK_LOCAL_NET = ipaddress.ip_network("169.254.0.0/16")


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
    r = run_cmd(["nmcli", "-t", "-f", "NAME,UUID,TYPE", "connection", "show"])
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
    ])
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
    fields = [
        "GENERAL.HWADDR",
        "GENERAL.STATE",
        "GENERAL.PRODUCT",
        "GENERAL.VENDOR",
        "WIFI-PROPERTIES.PERM-HW-ADDRESS",
    ]
    r = run_cmd(["nmcli", "-t", "-f", ",".join(fields), "device", "show", ifname])
    out: dict[str, str] = {}
    if r.returncode != 0:
        return out
    for line in r.stdout.splitlines():
        if not line:
            continue
        parts = split_nmcli_terse(line, maxsplit=1)
        if len(parts) != 2:
            continue
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

    Prefers a classified built-in; falls back to an adapter literally named
    ``wlan0`` when classification is inconclusive.
    """
    builtins = [a for a in adapters if a.is_builtin]
    if builtins:
        # Deterministic if (unexpectedly) more than one.
        return sorted(builtins, key=lambda a: a.stable_id)[0]
    for a in adapters:
        if a.ifname == BUILTIN_FALLBACK_IFNAME:
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
# Interface-aware health and routing primitives (WP2)
# ===========================================================================

def _is_rfc1918_ipv4(ip: ipaddress.IPv4Address) -> bool:
    return any(ip in n for n in _RFC1918_NETS)


def _nmcli_dev_show_fields(ifname: str, fields: list[str]) -> dict[str, list[str]]:
    """Return selected ``nmcli -t ... dev show <ifname>`` fields.

    Maps each base field name to a list of values (nmcli can emit indexed keys
    like IP4.ADDRESS[1], IP4.ADDRESS[2]).
    """
    r = run_cmd(["nmcli", "-t", "-f", ",".join(fields), "device", "show", ifname])
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
                prime_fn(gw)
            except Exception:
                pass

        neigh = _run_ip_json(["neigh", "show", "to", gw, "dev", ifname])
        for n in neigh:
            if n.get("dev") == ifname and (_stateset(n.get("state")) & _OK_NEIGH_STATES):
                return True
        return False
    except Exception as e:
        logger.warning("Interface gateway reachability check failed on %s: %s", ifname, e)
        return False


def get_active_wifi_connection_name(ifname: str) -> str:
    """Active connection profile name on *ifname*, or "" if unknown."""
    r = run_cmd(["nmcli", "-t", "-f", "DEVICE,TYPE,STATE,CONNECTION", "device", "status"])
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


def get_active_wifi_ssid(ifname: str) -> str:
    """SSID currently in use on *ifname*, or "" if unknown."""
    r = run_cmd(["nmcli", "-t", "-f", "IN-USE,SSID", "device", "wifi", "list", "ifname", ifname])
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


def is_wifi_connected(ifname: str) -> bool:
    """True if *ifname* is connected to a non-AP Wi-Fi network."""
    result = run_cmd(["nmcli", "-t", "-f", "DEVICE,TYPE,STATE,CONNECTION", "device", "status"])
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
        mode_result = run_cmd(["nmcli", "-t", "-f", "802-11-wireless.mode", "connection", "show", conn])
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


def delete_connection_cmd(connection_uuid: str) -> list[str]:
    return ["nmcli", "connection", "delete", "uuid", connection_uuid]


def get_connection_uuid_by_name_cmd(name: str) -> list[str]:
    return ["nmcli", "-t", "-f", "NAME,UUID", "connection", "show", name]
