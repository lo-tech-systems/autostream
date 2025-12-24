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

logger = logging.getLogger(__name__)

SDCARD_HEALTH_USED_FILE = Path("/opt/autostream/sdcardhealth")


# ---------------------------------------------------------------------------
# Command helpers
# ---------------------------------------------------------------------------

def run_cmd(
    cmd: list[str],
    timeout: float | None = None,
    log_cmd: list[str] | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run a command, logging stderr on failure, but never raising.

    Returns a CompletedProcess for further inspection.
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
        if result.returncode != 0:
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


# ---------------------------------------------------------------------------
# Reboot request helper
# ---------------------------------------------------------------------------

def reboot_system(reason: str = "UserRequestNormal") -> None:
    """
    Signal that a reboot is required by writing a marker file.
    Possible values for `reason`:
        AutostreamUpdate
        UserRequestNormal
        UserRequestSystemError
        NetworkDown
    """
    path = "/tmp/rebootrequired"
    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write(reason)
        logger.info("Reboot requested: %s", reason)
    except Exception:
        logger.exception("Failed to write reboot request file")


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


def get_sdcard_health_percent() -> int | None:
    """
    Return SD card health as a percent (100 - percent_used), or None if unavailable/invalid.

    Input file is expected to contain ONLY an integer 0..100 representing percent used.
    """
    try:
        if not SDCARD_HEALTH_USED_FILE.is_file():
            return None

        raw = SDCARD_HEALTH_USED_FILE.read_text(encoding="utf-8").strip()
        if not raw:
            return None

        used = int(raw, 10)
        if used < 0 or used > 100:
            return None

        return 100 - used
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


def _force_mdns_announce(new_hostname: str) -> None:
    """Best-effort mDNS refresh for the new hostname, without reboot.

    On typical Linux systems using Avahi:
      - avahi-set-host-name broadcasts the new hostname over mDNS.
      - As a fallback, we try to restart avahi-daemon.
    All of this is best-effort and quietly ignored if not available.
    """
    try:
        if shutil.which("avahi-set-host-name"):
            subprocess.run(
                ["avahi-set-host-name", new_hostname],
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        elif shutil.which("systemctl"):
            subprocess.run(
                ["systemctl", "try-restart", "avahi-daemon.service"],
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
    except Exception as e:  # noqa: BLE001
        logging.warning("Failed to trigger mDNS announcement: %s", e)


def set_system_hostname(new_hostname: str) -> None:
    """Set the system hostname and trigger mDNS announcements.

    Assumes autostream_webui is running with sufficient privileges.
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

    # Prefer systemd's hostnamectl if available
    if shutil.which("hostnamectl"):
        subprocess.run(
            ["hostnamectl", "set-hostname", new_hostname],
            check=True,
        )
    else:
        # Fallback: write /etc/hostname and call `hostname`
        try:
            with open("/etc/hostname", "w", encoding="utf-8") as f:
                f.write(new_hostname + "\n")
            subprocess.run(["hostname", new_hostname], check=True)
        except Exception as e:  # noqa: BLE001
            raise RuntimeError(f"Failed to set hostname: {e}") from e

    # Best effort: cause mDNS to re-announce the new hostname
    _force_mdns_announce(new_hostname)


# ---------------------------------------------------------------------------
# File handling functions.
# ---------------------------------------------------------------------------

def tail_lines(path: str, n: int = 100) -> str:
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

