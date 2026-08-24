"""autostream_licensing.py

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.

CPU-locked licensing: records the CPU serial expected for this install
(``CPU_INFO``) and checks the running device's CPU serial against it.

Split out of ``core/autostream_rpi.py``, which re-exports these names for
existing importers. A standalone product concept with no natural home in
another domain module -- named plainly here rather than folded into one.
Pure code motion -- no logic changed from the original module.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from autostream_system_stats import get_cpu_serial

logger = logging.getLogger(__name__)

CPU_INFO = Path("/var/lib/autostream/cpuinfo")
LICENSE_CHECK = False


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
