"""autostream_sysutils.py

Copyright (c) 2025 Lo-tech Systems Limited. All rights reserved.

This module contains system-level functions e.g. reboot helper
"""


from pathlib import Path
import subprocess
import shutil
import socket
import re
import logging
import os
import tempfile
import time
import json
from dataclasses import dataclass
from typing import Callable, IO, Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Atomic file writer
# ---------------------------------------------------------------------------

def atomic_write_file(
    path: "str | Path",
    writer: Callable[[IO], None],
    *,
    preserve_mode: bool = True,
) -> None:
    """Write to *path* atomically: temp file → writer() → fsync → os.replace.

    *writer* receives an open text-mode file object and is responsible for
    writing all content.  The destination file is only replaced once the
    write and fsync have both succeeded, so a crash or kill mid-write leaves
    the original file intact.

    If *preserve_mode* is True (the default) and the destination file already
    exists, its permission bits are copied to the temporary file before the
    rename so the replacement inherits the same mode.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    mode: Optional[int] = None
    if preserve_mode:
        try:
            mode = path.stat().st_mode
        except FileNotFoundError:
            pass
        except Exception:
            pass

    fd, tmp_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=str(path.parent),
    )
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            writer(fh)
            fh.flush()
            os.fsync(fh.fileno())

        if mode is not None:
            try:
                os.chmod(tmp, mode)
            except Exception:
                logger.warning("atomic_write_file: could not apply mode to %s", tmp)

        os.replace(tmp, path)
    except Exception:
        try:
            tmp.unlink()
        except OSError:
            pass
        raise

SDCARD_HEALTH_JSON_FILE = Path("/var/lib/autostream/sdcardhealth.json")
OS_RELEASE_FILE = Path("/etc/os-release")

# Privileged helper (installed outside /opt/autostream)
AUTOSTREAM_ADMIN_BIN = os.environ.get("AUTOSTREAM_ADMIN_BIN", "/usr/local/libexec/autostream/autostream_admin")


@dataclass(frozen=True)
class StaticSystemFacts:
    os_pretty_name: str = "unknown"
    os_version_id: str = "unknown"
    os_version_codename: str = "unknown"
    raspberry_pi_model: str = "unknown"
    nginx_version: str = "unknown"


_static_system_facts: StaticSystemFacts | None = None


# ---------------------------------------------------------------------------
# AP SSID helper
# ---------------------------------------------------------------------------

def get_ap_ssid(ifname: str = "wlan0") -> str:
    """Return the AP SSID for the given interface based on its MAC address.

    Format: autostream_XXXX where XXXX are the last four hex digits of the MAC.
    Falls back to autostream_SETUP if the MAC cannot be read.
    """
    try:
        mac = Path(f"/sys/class/net/{ifname}/address").read_text(
            encoding="ascii", errors="ignore"
        ).strip().replace(":", "")
        suffix = mac[-4:].upper() if len(mac) >= 4 else "0000"
        return f"autostream_{suffix}"
    except Exception:
        return "autostream_SETUP"

# ---------------------------------------------------------------------------
# Command helpers
# ---------------------------------------------------------------------------

def run_cmd(
    cmd: list[str],
    timeout: float | None = None,
    log_cmd: list[str] | None = None,
    warn_on_failure: bool = True,
) -> subprocess.CompletedProcess[str]:
    """Run a command, logging stderr on failure, but never raising.

    Returns a CompletedProcess for further inspection.
    Pass warn_on_failure=False for best-effort probes whose failure is expected
    and should not appear in the log (e.g. optional nmcli fields absent from
    older NetworkManager builds).
    """
    safe_cmd = log_cmd if log_cmd is not None else cmd
    try:
        kwargs: dict = {
            "capture_output": True,
            "text": True,
        }
        if timeout is not None:
            kwargs["timeout"] = timeout

        result: subprocess.CompletedProcess[str] = subprocess.run(
            cmd,
            **kwargs,
        )
        if result.returncode != 0 and warn_on_failure:
            logger.warning(
                "Command failed: %s (rc=%s, stderr=%s)",
                " ".join(safe_cmd),
                result.returncode,
                (result.stderr or "").strip(),
            )
        return result
    except subprocess.TimeoutExpired:
        logger.warning(
            "Command timed out: %s (timeout=%ss)",
            " ".join(safe_cmd),
            timeout,
        )
        # Provide a consistent return type.
        return subprocess.CompletedProcess(
            cmd,
            124,  # common timeout rc (like GNU timeout)
            stdout="",
            stderr=f"timeout after {timeout}s" if timeout is not None else "timeout",
        )
    except Exception:
        logger.exception("Exception while running command: %s", " ".join(safe_cmd))
        # Provide a consistent return type.
        return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="")

_last_prime: dict[tuple[str, str], float] = {}

def prime_gateway(gw: str, ifname: str, min_interval: float = 5.0) -> None:
    """Send a single ping through *ifname* to populate the kernel neighbour table.

    Keyed by (gw, ifname) so priming one interface does not suppress priming
    another that shares the same gateway address.  We do not treat ping
    success/failure as connectivity evidence; it only nudges the neighbour cache.
    """
    if not gw or not ifname:
        return
    try:
        now = time.monotonic()
        key = (gw, ifname)
        last = _last_prime.get(key, 0.0)
        if now - last < min_interval:
            return
        # A no-reply exit (ping rc=1) is an expected outcome for a best-effort
        # nudge, not a command failure, so it must not log a WARNING; the
        # health verdict comes from the neighbour-table state afterwards.
        result = run_cmd(
            ["ping", "-I", ifname, "-c", "1", "-W", "1", gw],
            timeout=2, warn_on_failure=False,
        )
        if result.returncode != 0:
            logger.debug(
                "Gateway prime ping got no reply on %s (gw=%s, rc=%s)",
                ifname, gw, result.returncode,
            )
        _last_prime[key] = now
    except Exception:
        # Never fail hard due to priming; it's a best-effort nudge.
        pass



# ---------------------------------------------------------------------------
# Privileged helper wrapper (sudo)
# ---------------------------------------------------------------------------

def run_admin_cmd(
    args: list[str],
    timeout: float | None = 10.0,
) -> subprocess.CompletedProcess[str]:
    """Run autostream_admin via sudo (non-interactive).

    This assumes a tight sudoers rule for the web user, and that the helper is
    installed at AUTOSTREAM_ADMIN_BIN (default /usr/local/libexec/autostream/autostream_admin).
    """
    cmd = ["sudo", "-n", AUTOSTREAM_ADMIN_BIN, *args]
    # For logs, avoid leaking the full filesystem path if you prefer;
    # but keep enough detail to diagnose failures.
    log_cmd = ["sudo", "-n", "autostream_admin", *args]
    return run_cmd(cmd, timeout=timeout, log_cmd=log_cmd)


# ---------------------------------------------------------------------------
# Startup system diagnostics
# ---------------------------------------------------------------------------

def _strip_env_quotes(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in ('"', "'"):
        value = value[1:-1]
    return value


def get_os_release_info(path: Path | str = OS_RELEASE_FILE) -> dict[str, str]:
    """Parse /etc/os-release without sourcing it."""
    info = {
        "pretty_name": "unknown",
        "version_id": "unknown",
        "version_codename": "unknown",
    }
    try:
        for raw in Path(path).read_text(encoding="utf-8", errors="replace").splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            key = key.strip()
            value = _strip_env_quotes(value)
            if key == "PRETTY_NAME":
                info["pretty_name"] = value or "unknown"
            elif key == "VERSION_ID":
                info["version_id"] = value or "unknown"
            elif key == "VERSION_CODENAME":
                info["version_codename"] = value or "unknown"
    except Exception:
        pass
    return info


def get_nginx_version() -> str:
    """Return the installed NGINX version string, or "unknown" if unavailable."""
    result = run_cmd(["nginx", "-v"], timeout=2.0, warn_on_failure=False)
    if result.returncode != 0:
        return "unknown"
    text = " ".join(
        part.strip()
        for part in (result.stderr, result.stdout)
        if part and part.strip()
    )
    if not text:
        return "unknown"
    m = re.search(r"nginx version:\s*(\S+)", text)
    if m:
        return m.group(1).strip() or "unknown"
    m = re.search(r"\b(nginx/\S+)", text)
    if m:
        return m.group(1).strip() or "unknown"
    return "unknown"


def audit_static_system_facts() -> StaticSystemFacts:
    """Collect startup static system facts once, store them, and log them."""
    global _static_system_facts

    os_info = get_os_release_info()
    try:
        from autostream_rpi import get_raspberry_pi_model
        rpi_model = get_raspberry_pi_model()
    except Exception:
        rpi_model = "unknown"

    facts = StaticSystemFacts(
        os_pretty_name=os_info.get("pretty_name") or "unknown",
        os_version_id=os_info.get("version_id") or "unknown",
        os_version_codename=os_info.get("version_codename") or "unknown",
        raspberry_pi_model=rpi_model or "unknown",
        nginx_version=get_nginx_version(),
    )
    _static_system_facts = facts

    logger.info(
        "System audit: OS=%r version_id=%s codename=%s",
        facts.os_pretty_name,
        facts.os_version_id,
        facts.os_version_codename,
    )
    logger.info("System audit: Device=%r", facts.raspberry_pi_model)
    logger.info("System audit: NGINX version=%r", facts.nginx_version)
    return facts


def get_static_system_facts() -> StaticSystemFacts:
    """Return the startup-collected static system facts, or unknown defaults."""
    return _static_system_facts or StaticSystemFacts()



# ---------------------------------------------------------------------------
# Reboot request helper
# ---------------------------------------------------------------------------

def reboot_system(reason: str = "UserRequestNormal", delay_s: int | None = None) -> bool:
    """Request a reboot via the privileged autostream_admin helper.

    Returns True if the reboot was accepted, False if rate-limited or failed.
    Possible values for `reason`: AutostreamUpdate, UserRequestNormal,
    UserRequestSystemError, NetworkDown.
    """
    reason = (reason or "").strip()
    if not reason:
        reason = "UserRequestNormal"

    args: list[str] = ["reboot"]
    if delay_s is not None:
        try:
            d = int(delay_s)
        except Exception:
            d = 0
        if d > 0:
            args += ["--delay", str(d)]

    args.append(reason)

    p = run_admin_cmd(args, timeout=10.0)
    if p.returncode == 0:
        if delay_s and int(delay_s) > 0:
            logger.info("Delayed reboot requested via autostream_admin: delay=%ss reason=%s", delay_s, reason)
        else:
            logger.info("Reboot requested via autostream_admin: %s", reason)
        return True

    if p.returncode == 2:
        logger.info(
            "Reboot request rate-limited by autostream_admin: %s (will retry later)",
            reason,
        )
        return False

    logger.error(
        "Reboot request via autostream_admin failed (rc=%s, stderr=%s)",
        p.returncode,
        (p.stderr or "").strip(),
    )
    return False


# ---------------------------------------------------------------------------
# Factory reset request helper
# ---------------------------------------------------------------------------

def factory_reset_system() -> None:
    """Request a factory reset via the privileged autostream_admin helper.

    The helper schedules the actual reset as a transient systemd unit (to
    escape the autostream.service cgroup) and returns immediately, so this
    function returns before the reset sequence begins. The caller should
    navigate the user to the nginx-served /offline/resetting holding page
    immediately after calling this function.

    Raises RuntimeError if the scheduling call fails.
    """
    p = run_admin_cmd(["factory-reset"], timeout=15.0)
    if p.returncode == 0:
        logger.info("Factory reset scheduled via autostream_admin")
        return
    raise RuntimeError(
        f"Factory reset scheduling failed via autostream_admin "
        f"(rc={p.returncode}): {(p.stderr or '').strip()}"
    )


# ---------------------------------------------------------------------------
# Disk space & health related functions.
# ---------------------------------------------------------------------------

def get_root_disk_usage() -> tuple[int, int, int] | None:
    """Return (total_bytes, used_bytes, free_bytes) for the root filesystem, or None if unavailable."""
    try:
        du = shutil.disk_usage("/")
        return du.total, du.used, du.free
    except Exception:
        return None


def fmt_bytes(n: int) -> str:
    """Human-friendly bytes (GiB)."""
    try:
        gib = n / (1024**3)
        return f"{gib:.1f} GB"
    except Exception:
        return str(n)


def _coerce_float(value) -> float | None:
    try:
        return float(value)
    except Exception:
        return None


def _coerce_bool(value) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        v = value.strip().lower()
        if v in {"true", "yes", "1"}:
            return True
        if v in {"false", "no", "0"}:
            return False
    return None


def _parse_sdcard_health_percent(data: dict) -> int | None:
    success = _coerce_bool(data.get("success"))
    if success is not True:
        return None

    remaining: float | None = None

    if "enduranceRemainLifePercent" in data:
        remaining = _coerce_float(data.get("enduranceRemainLifePercent"))
    elif "healthStatusPercentUsed" in data:
        used = _coerce_float(data.get("healthStatusPercentUsed"))
        if used is not None:
            remaining = 100.0 - used

    if remaining is None:
        return None

    if remaining < -0.5 or remaining > 100.5:
        return None

    return max(0, min(100, int(round(remaining))))


def get_sdcard_health_percent() -> int | None:
    """
    Return SD card remaining health as a rounded whole percent, or None if unavailable.

    Input file is expected to contain the full sdmon JSON output.
    """
    try:
        if not SDCARD_HEALTH_JSON_FILE.is_file():
            return None

        raw = SDCARD_HEALTH_JSON_FILE.read_text(encoding="utf-8").strip()
        if not raw:
            return None

        data = json.loads(raw)
        if not isinstance(data, dict):
            return None

        return _parse_sdcard_health_percent(data)
    except Exception:
        return None

# ---------------------------------------------------------------------------
# System Hostname Related functions.
# ---------------------------------------------------------------------------

def get_system_hostname() -> str:
    """Return the current system hostname."""
    try:
        return socket.gethostname()
    except Exception:
        return ""



def set_system_hostname(new_hostname: str) -> None:
    """Set the system hostname and trigger mDNS announcements.

    Uses the privileged autostream_admin helper via sudo.
    """
    new_hostname = new_hostname.strip()
    if not new_hostname:
        return

    # conservative RFC 952/1123-style hostname validation
    if not re.fullmatch(
        r"[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
        r"(?:\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*",
        new_hostname,
    ):
        raise ValueError("Invalid hostname")

    p = run_admin_cmd(["sethostname", new_hostname], timeout=15.0)
    if p.returncode == 0:
        logger.info("Hostname change requested via autostream_admin: %s", new_hostname)
        return
    raise RuntimeError(
        f"Failed to set hostname via autostream_admin (rc={p.returncode}): {(p.stderr or '').strip()}"
    )

# ---------------------------------------------------------------------------
# File handling functions.
# ---------------------------------------------------------------------------

def tail_lines(path: str, n: int = 100) -> list[str]:
    """Return the last n lines of a text file efficiently."""
    try:
        with open(path, "rb") as f:
            f.seek(0, os.SEEK_END)
            end = f.tell()
            size = 1024
            data = b""
            while end > 0 and data.count(b"\n") <= n:
                start = max(0, end - size)
                f.seek(start)
                chunk = f.read(end - start)
                data = chunk + data
                end = start
            return data.decode("utf-8", errors="replace").splitlines()[-n:]
    except Exception as e:
        return [f"[Error reading log file: {e}]"]


# ---------------------------------------------------------------------------
# Install state helpers
# ---------------------------------------------------------------------------

def get_install_state(path) -> dict:
    """Parse a KEY=VALUE env file without sourcing it.

    Strips surrounding single/double quotes from values; skips blank lines
    and lines beginning with '#'.  Returns a plain str→str dict.
    Silent on FileNotFoundError.
    """
    result: dict[str, str] = {}
    try:
        with open(path, encoding="utf-8") as fh:
            for raw in fh:
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" not in line:
                    continue
                key, _, value = line.partition("=")
                key = key.strip()
                value = value.strip()
                if len(value) >= 2 and value[0] == value[-1] and value[0] in ('"', "'"):
                    value = value[1:-1]
                if key:
                    result[key] = value
    except FileNotFoundError:
        pass
    except Exception:
        logger.warning("get_install_state: could not read %s", path)
    return result


# ---------------------------------------------------------------------------
# Avahi playing-state helpers (mDNS service file lifecycle)
# ---------------------------------------------------------------------------

def write_avahi_playing_service(version: str) -> bool:
    """Call sudo autostream_admin write-playing-service <version>.

    Returns True on success.  Logs at WARNING on failure; never raises.
    """
    p = run_admin_cmd(["write-playing-service", version], timeout=10.0)
    if p.returncode == 0:
        return True
    logger.warning(
        "write_avahi_playing_service: admin call failed (rc=%s)", p.returncode
    )
    return False


def remove_avahi_playing_service() -> bool:
    """Call sudo autostream_admin remove-playing-service.

    Returns True on success.  Logs at WARNING on failure; never raises.
    """
    p = run_admin_cmd(["remove-playing-service"], timeout=10.0)
    if p.returncode == 0:
        return True
    logger.warning(
        "remove_avahi_playing_service: admin call failed (rc=%s)", p.returncode
    )
    return False


def set_nginx_verbose_logging(enabled: bool) -> bool:
    """Switch NGINX access logging between verbose (all requests) and normal (2xx suppressed).

    Calls autostream_admin set-nginx-access-log verbose|normal via sudo.
    Returns True on success; False on any failure.  Non-fatal: logs a warning.
    """
    mode = "verbose" if enabled else "normal"
    p = run_admin_cmd(["set-nginx-access-log", mode], timeout=10.0)
    if p.returncode == 0:
        return True
    logger.warning(
        "set_nginx_verbose_logging: admin call failed (rc=%s, mode=%s)", p.returncode, mode
    )
    return False


# Success marker for the journald DIAG-tier toggle. Written ONLY after the
# privileged admin call fully succeeded (drop-in written/removed AND journald
# restarted). Deliberately NOT the drop-in file itself: the admin script can
# write/remove the drop-in and then fail the journald restart, and inferring
# state from the drop-in's existence would short-circuit every later call and
# permanently mask the failed restart. Removed by the installer/uninstaller
# alongside the zz- override so an upgrade reset cannot be masked either.
_JOURNALD_STATE_MARKER = Path("/var/lib/autostream/journald-persistent.applied")


def set_journald_persistent(enabled: bool) -> bool:
    """Couple persistent journald storage to the DIAG (debug/spam) log tier.

    When *enabled* is True, writes a higher-priority drop-in
    (/etc/systemd/journald.conf.d/zz-autostream-diag-persistent.conf, sorting after
    99-autostream-storage.conf) forcing Storage=persistent and restarts
    systemd-journald. When False, removes the drop-in (falling back to the
    volatile baseline), restarts journald, and best-effort reclaims the
    persisted DIAG data.

    Calls autostream_admin set-journald-persistent on|off via sudo, mirroring
    set_nginx_verbose_logging's privilege mechanism. A success marker (see
    _JOURNALD_STATE_MARKER) makes repeat calls with an unchanged desired state
    free -- no sudo call, no journald restart -- while a failed or partial
    apply leaves no marker, so the next apply (including the storage guard's
    pending-reapply retry) re-drives the admin helper. Returns True on success
    (including already-applied); False on any failure. Non-fatal: logs a
    warning, never raises.
    """
    mode = "on" if enabled else "off"

    try:
        if _JOURNALD_STATE_MARKER.read_text(encoding="utf-8").strip() == mode:
            return True  # last fully-successful apply matches; nothing to do
    except OSError:
        pass  # no marker (or unreadable): fall through to the admin helper

    p = run_admin_cmd(["set-journald-persistent", mode], timeout=15.0)
    if p.returncode == 0:
        try:
            _JOURNALD_STATE_MARKER.write_text(mode + "\n", encoding="utf-8")
        except OSError as e:
            # Marker write failure just means the next apply repeats the
            # (idempotent) admin call; log and carry on.
            logger.warning(
                "set_journald_persistent: could not write state marker: %s", e
            )
        return True
    logger.warning(
        "set_journald_persistent: admin call failed (rc=%s, mode=%s)", p.returncode, mode
    )
    return False


# ---------------------------------------------------------------------------
# Bluetooth privileged actions
# ---------------------------------------------------------------------------

def bt_services_enable() -> tuple[bool, str]:
    """Unmask, enable, and start the Bluetooth service set via autostream_admin.

    Calls `sudo autostream_admin bt-services-enable`, which unmasks/enables
    bluetooth.service, enables the bluealsa unit, disables bluealsa-aplay
    (it conflicts with our own capture pump), and enables+starts
    autostream_bluetooth.service. Returns (ok, human-readable message).
    """
    p = run_admin_cmd(["bt-services-enable"], timeout=30.0)
    if p.returncode == 0:
        return True, "Bluetooth services enabled."
    logger.warning("bt_services_enable: admin call failed (rc=%s)", p.returncode)
    return False, "Failed to enable Bluetooth services."


def bt_services_disable() -> tuple[bool, str]:
    """Disable and stop the Bluetooth service set via autostream_admin.

    Calls `sudo autostream_admin bt-services-disable`. Stopping
    bluetooth.service drops any active A2DP stream immediately; pairing
    bonds are preserved for re-enable. Returns (ok, human-readable message).
    """
    p = run_admin_cmd(["bt-services-disable"], timeout=30.0)
    if p.returncode == 0:
        return True, "Bluetooth services disabled."
    logger.warning("bt_services_disable: admin call failed (rc=%s)", p.returncode)
    return False, "Failed to disable Bluetooth services."


def bt_onboard_set(enabled: bool) -> tuple[bool, str]:
    """Toggle the onboard Bluetooth radio (config.txt dtoverlay=disable-bt).

    Calls `sudo autostream_admin bt-onboard-on|bt-onboard-off`. The change
    only takes effect after a reboot, which this function does not perform
    -- the caller drives the existing reboot holding-page flow. Returns
    (ok, human-readable message); the message notes whether a reboot is
    actually required (idempotent calls that changed nothing do not need one).
    """
    verb = "bt-onboard-on" if enabled else "bt-onboard-off"
    state = "enabled" if enabled else "disabled"
    p = run_admin_cmd([verb], timeout=30.0)
    if p.returncode != 0:
        logger.warning("bt_onboard_set: admin call failed (rc=%s, verb=%s)", p.returncode, verb)
        return False, f"Failed to set onboard Bluetooth ({state})."

    out = (p.stdout or "").strip()
    if out == "reboot-required":
        return True, f"Onboard Bluetooth {state}; a reboot is required to take effect."
    return True, f"Onboard Bluetooth already {state}."
