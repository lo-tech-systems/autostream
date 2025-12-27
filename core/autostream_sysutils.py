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

# Privileged helper (installed outside /opt/autostream)
AUTOSTREAM_ADMIN_BIN = os.environ.get("AUTOSTREAM_ADMIN_BIN", "/usr/local/libexec/autostream/autostream_admin")

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
# Privileged helper wrapper (sudo)
# ---------------------------------------------------------------------------

def run_admin_cmd(
    args: list[str],
    timeout: float | None = 10.0,
) -> subprocess.CompletedProcess[str]:
    """Run autostream_admin via sudo (non-interactive).

    This assumes a tight sudoers rule for the web user, and that the helper is
    installed at AUTOSTREAM_ADMIN_BIN (default /usr/local/sbin/autostream_admin).
    """
    cmd = ["sudo", "-n", AUTOSTREAM_ADMIN_BIN, *args]
    # For logs, avoid leaking the full filesystem path if you prefer;
    # but keep enough detail to diagnose failures.
    log_cmd = ["sudo", "-n", "autostream_admin", *args]
    return run_cmd(cmd, timeout=timeout, log_cmd=log_cmd)



# ---------------------------------------------------------------------------
# Reboot request helper
# ---------------------------------------------------------------------------

def reboot_system(reason: str = "UserRequestNormal") -> None:
    """
    Request a reboot via the privileged autostream_admin helper.
    Possible values for `reason`:
        AutostreamUpdate
        UserRequestNormal
        UserRequestSystemError
        NetworkDown
    """
    reason = (reason or "").strip()
    if not reason:
        reason = "UserRequestNormal"
    p = run_admin_cmd(["reboot", reason], timeout=10.0)
    if p.returncode == 0:
        logger.info("Reboot requested via autostream_admin: %s", reason)
        return
    logger.error(
        "Reboot request via autostream_admin failed (rc=%s, stderr=%s)",
        p.returncode,
        (p.stderr or "").strip(),
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

