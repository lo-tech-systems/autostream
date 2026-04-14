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

SDCARD_HEALTH_JSON_FILE = Path("/opt/autostream/sdcardhealth.json")

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

_last_prime: dict[str, float] = {}

def prime_gateway(gw: str, min_interval: float = 5.0) -> None:
    """
    Generate minimal traffic to the gateway to populate/update the kernel neighbor table.
    We do not treat ping success/failure as connectivity by itself; it only primes state.
    """
    if not gw:
        return
    try:
        now = time.monotonic()
        last = _last_prime.get(gw, 0.0)
        if now - last < min_interval:
            return
        run_cmd(["ping", "-c", "1", "-W", "1", gw], timeout=2)
        _last_prime[gw] = now
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

def reboot_system(reason: str = "UserRequestNormal", delay_s: int | None = None) -> None:
    """
    Request a reboot via the privileged autostream_admin helper.
    Possible values for `reason`:
        AutostreamUpdate
        UserRequestNormal
        UserRequestSystemError
        NetworkDown

    If delay_s is a positive integer, request a delayed reboot using the helper's
    `reboot --delay SECONDS [reason]` option.
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
