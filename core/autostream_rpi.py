"""autostream_rpi.py

Copyright (c) 2025 Lo-tech Systems Limited. All rights reserved.

Functions specific to the Raspberry Pi platform integration e.g. PSU checks.
"""

from __future__ import annotations

import logging
import os
import time
from pathlib import Path
import subprocess
from dataclasses import dataclass
from typing import Iterable, Optional

from autostream_sysutils import run_cmd


logger = logging.getLogger(__name__)

CPU_INFO = Path("/opt/autostream/cpuinfo")
LICENSE_CHECK = False


# ---------------------------------------------------------------------------
# Raspberry Pi PSU check related functions.
# ---------------------------------------------------------------------------

import threading
_psu_seen_lock = threading.Lock()
_seen_historic_undervolt = False

# Cache state
_GET_THROTTLED_CACHE_VALUE: Optional[int] = None
_GET_THROTTLED_CACHE_TIME: float = 0.0
_GET_THROTTLED_CACHE_TTL = 30.0  # seconds

def _parse_throttled_mask(throttled: int):
    # Current status bits (0..2)
    current = throttled & 0x7

    # “Has occurred” historic bits (16..18) mapped down to 0..2
    historic = (throttled >> 16) & 0x7

    return current, historic

def _read_get_throttled_value() -> Optional[int]:
    """
    Return the raw get_throttled value as an int, or None if unavailable.
    Value is cached and re-read from the system at most once every 30 seconds.
    """
    global _GET_THROTTLED_CACHE_VALUE, _GET_THROTTLED_CACHE_TIME

    now = time.monotonic()
    if (now - _GET_THROTTLED_CACHE_TIME) < _GET_THROTTLED_CACHE_TTL:
        return _GET_THROTTLED_CACHE_VALUE

    value: Optional[int] = None

    # Prefer sysfs if present
    sysfs_path = "/sys/devices/platform/soc/soc:firmware/get_throttled"
    try:
        if os.path.isfile(sysfs_path):
            raw = open(sysfs_path, "r", encoding="utf-8").read().strip()
            value = int(raw, 0)  # handles "0x..." or decimal
    except Exception:
        value = None

    # Fallback to vcgencmd if sysfs failed
    if value is None:
        try:
            p = subprocess.run(
                ["vcgencmd", "get_throttled"],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                timeout=2,
                check=False,
            )
            s = (p.stdout or "").strip()
            # expected: "throttled=0x50005"
            if "0x" in s:
                hexpart = s.split("0x", 1)[1]
                value = int("0x" + hexpart, 16)
        except Exception:
            value = None

    # Update cache (even if None)
    _GET_THROTTLED_CACHE_VALUE = value
    _GET_THROTTLED_CACHE_TIME = now

    return value

def get_psu_warning_text() -> Optional[str]:
    throttled = _read_get_throttled_value()
    if throttled is None:
        return None

    current, historic = _parse_throttled_mask(throttled)

    # Test for undervoltage
    current_uv = bool(current & 0x1)
    historic_uv = bool(historic & 0x1)

    # 2) Always show current failures (undervoltage happening now)
    if current_uv:
        return "⚠  PSU undervoltage detected. Replace PSU/cable."

    # 1) Show historic failure only once (undervoltage occurred previously)
    if historic_uv:
        global _seen_historic_undervolt
        with _psu_seen_lock:
            if _seen_historic_undervolt:
                return None
            _seen_historic_undervolt = True

        return "⚠  PSU undervoltage has occurred since last boot. Check PSU/cable."

    return None


# ---------------------------------------------------------------------------
# CPU serial number functions. Used to discourage copying the SD-Card.
# ---------------------------------------------------------------------------


def _first_non_empty(lines: Iterable[str]) -> str:
    for s in lines:
        s2 = s.strip()
        if s2:
            return s2
    return ""


def get_cpu_serial() -> str:
    """Return the CPU serial number.

    Tries /proc/cpuinfo first, then /proc/device-tree/serial-number.
    Returns "" if not found.
    """
    # Method 1: /proc/cpuinfo
    try:
        cpuinfo = Path("/proc/cpuinfo").read_text(encoding="utf-8", errors="ignore")
        for ln in cpuinfo.splitlines():
            if ln.strip().lower().startswith("serial"):
                # Expected format: "Serial\t\t: 00000000abcdef"
                parts = ln.split(":", 1)
                if len(parts) == 2:
                    serial = parts[1].strip()
                    if serial:
                        return serial
                break
    except Exception:
        pass

    # Method 2: device tree (common on Raspberry Pi)
    try:
        raw = Path("/proc/device-tree/serial-number").read_bytes()
        if raw:
            return raw.replace(b"\x00", b"").decode("utf-8", errors="ignore").strip()
    except Exception:
        pass

    return ""



# ---------------------------------------------------------------------------
# CPU licensing
# ---------------------------------------------------------------------------

@dataclass
class _CpuLicenseCache:
    ok: bool = False


_CPU_LICENSE_CACHE = _CpuLicenseCache()


def _read_expected_serial() -> str:
    if not CPU_INFO.is_file():
        return ""
    try:
        return CPU_INFO.read_text(encoding="utf-8").strip()
    except Exception:
        logger.exception("Failed reading %s", CPU_INFO)
        return ""


def cpu_matches() -> bool:
    """Return True if this device's CPU serial matches the stored expected serial."""
    expected = _read_expected_serial()
    if not expected:
        return False

    current = get_cpu_serial()

    if current == expected:
        return True

    logger.info("CPU identity does not match expected value")
    return False


def cpu_is_licensed(cpu_matcher: Optional[callable] = None) -> bool:
    """Return True if the CPU is licensed.

    The function caches a positive result in-process.

    Parameters
    ----------
    cpu_matcher:
        Optional callable used to check CPU identity. Defaults to `cpu_matches`.
        This makes it easy for callers/tests to inject alternative checks.
    """
    if _CPU_LICENSE_CACHE.ok:
        return True

    matcher = cpu_matcher or cpu_matches

    try:
        ok = bool(matcher())
    except Exception:
        logger.exception("CPU license check failed")
        ok = False

    if ok:
        _CPU_LICENSE_CACHE.ok = True
        return True

    return False


# ---------------------------------------------------------------------------
# CPU_INFO initialization
# ---------------------------------------------------------------------------

def check_cpu() -> None:
    """Ensure CPU_INFO exists and contains a serial if possible.

    - If CPU_INFO does not exist: create it with the current serial (possibly blank).
    - If CPU_INFO exists but is empty/whitespace: replace it with the current serial.
    - If CPU_INFO exists and is non-empty: do nothing.
    """
    serial = get_cpu_serial()

    # Create file if missing
    if not CPU_INFO.is_file():
        _write_cpu_info(serial)
        logger.info("Recorded CPU serial '%s' to %s", serial, CPU_INFO)
        return

    # Replace if empty
    existing = _read_expected_serial()
    if not existing:
        _write_cpu_info(serial)
        logger.info("Recorded CPU serial '%s' to %s", serial, CPU_INFO)


def _write_cpu_info(serial: str) -> None:
    try:
        CPU_INFO.parent.mkdir(parents=True, exist_ok=True)
        CPU_INFO.write_text((serial + "\n") if serial else "", encoding="utf-8")
    except Exception:
        logger.exception("Failed writing %s", CPU_INFO)


