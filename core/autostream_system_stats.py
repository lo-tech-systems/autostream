"""autostream_system_stats.py

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.

Raspberry Pi PSU/CPU/system fact readers: PSU undervoltage warning text,
CPU temperature, CPU busy percentage, the Pi model string, the CPU
serial number, and the audio-path SRC-tier hardware classification built
on that model string.

Split out of ``core/autostream_rpi.py``, which re-exports these names for
existing importers. This is one of four unrelated concerns the original
module mixed together -- appliance identity derivation
(``autostream_appliance_identity.py``), CPU licensing
(``autostream_licensing.py``), and dial GPIO helpers
(``autostream_dial_gpio.py``) are the other three. Pure code motion -- no
logic changed from the original module.
"""

from __future__ import annotations

import logging
import os
import subprocess
import threading
import time
from pathlib import Path
from typing import Iterable, Optional

logger = logging.getLogger(__name__)

RPI_MODEL_FILE = Path("/proc/device-tree/model")

# ---------------------------------------------------------------------------
# Raspberry Pi PSU check related functions.
# ---------------------------------------------------------------------------

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
            with open(sysfs_path, "r", encoding="utf-8") as _f:
                raw = _f.read().strip()
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


def get_cpu_temperature_c() -> Optional[float]:
    """Return the current CPU temperature in Celsius, or None if unavailable."""
    sysfs_path = "/sys/class/thermal/thermal_zone0/temp"
    try:
        if os.path.isfile(sysfs_path):
            raw = Path(sysfs_path).read_text(encoding="utf-8").strip()
            milli_c = int(raw)
            return round(milli_c / 1000.0, 1)
    except Exception:
        pass

    try:
        p = subprocess.run(
            ["vcgencmd", "measure_temp"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=2,
            check=False,
        )
        s = (p.stdout or "").strip()
        if "=" in s:
            raw_temp = s.split("=", 1)[1].split("'", 1)[0].strip()
            return round(float(raw_temp), 1)
    except Exception:
        pass

    return None


_CPU_BUSY_LOCK = threading.Lock()
# Cached previous /proc/stat sample: (total_jiffies, idle_jiffies, monotonic_time).
_CPU_BUSY_PREV_SAMPLE: Optional[tuple] = None

_CPU_BUSY_MIN_SAMPLE_AGE = 0.2   # seconds; below this the delta is too noisy to trust
_CPU_BUSY_MAX_SAMPLE_AGE = 300.0  # seconds; above this the sample is considered stale
_CPU_BUSY_FALLBACK_SLEEP = 0.25   # seconds; blocking two-sample measurement


def _read_proc_stat_cpu_totals() -> Optional[tuple]:
    """Read the aggregate 'cpu' line from /proc/stat and return
    (total_jiffies, idle_jiffies), or None if unavailable/unparsable.

    idle_jiffies is idle + iowait, matching how top/htop treat iowait as
    non-busy time.
    """
    try:
        with open("/proc/stat", "r", encoding="utf-8") as f:
            first_line = f.readline()
    except Exception:
        return None

    parts = first_line.split()
    if len(parts) < 5 or parts[0] != "cpu":
        return None

    try:
        fields = [float(x) for x in parts[1:]]
    except Exception:
        return None

    user, nice, system, idle = fields[0], fields[1], fields[2], fields[3]
    iowait = fields[4] if len(fields) > 4 else 0.0
    rest = sum(fields[5:]) if len(fields) > 5 else 0.0

    total = user + nice + system + idle + iowait + rest
    idle_total = idle + iowait
    return (total, idle_total)


def get_cpu_busy_percent() -> Optional[float]:
    """Return CPU utilisation (busy time) across all cores as a percentage,
    matching what top/htop report -- distinct from the scheduler load average
    (runnable + uninterruptible-IO-waiting task count) previously reported
    here, which reads misleadingly high (e.g. >100%) relative to affinity
    core count on this appliance.

    Computed as 100 * (non-idle delta / total delta) between two /proc/stat
    samples, where idle time includes iowait (iowait is counted as idle, the
    same convention top/htop use -- a CPU waiting on disk isn't "busy").

    This is called once per About page load, so no background thread is
    used. A module-level cache holds the previous sample; if it exists and
    is recent enough to give a meaningful delta (between ~0.2s and 5
    minutes old) it is used directly (near-zero added latency). Otherwise
    (first call, stale cache, or counters that went backwards e.g. after a
    counter wrap or /proc/stat anomaly) a short blocking two-sample
    measurement (~0.25s) is taken instead.
    """
    global _CPU_BUSY_PREV_SAMPLE

    now = time.monotonic()
    current = _read_proc_stat_cpu_totals()
    if current is None:
        return None
    total, idle = current

    with _CPU_BUSY_LOCK:
        prev = _CPU_BUSY_PREV_SAMPLE

    usable_prev = None
    if prev is not None:
        prev_total, prev_idle, prev_time = prev
        age = now - prev_time
        if (
            _CPU_BUSY_MIN_SAMPLE_AGE <= age <= _CPU_BUSY_MAX_SAMPLE_AGE
            and total >= prev_total
            and idle >= prev_idle
        ):
            usable_prev = (prev_total, prev_idle)

    if usable_prev is not None:
        prev_total, prev_idle = usable_prev
        total_delta = total - prev_total
        idle_delta = idle - prev_idle
        with _CPU_BUSY_LOCK:
            _CPU_BUSY_PREV_SAMPLE = (total, idle, now)
        if total_delta <= 0:
            return None
        busy_delta = total_delta - idle_delta
        pct = (busy_delta / total_delta) * 100.0
        return round(max(0.0, min(100.0, pct)), 1)

    # No usable previous sample: take a short blocking two-sample measurement.
    time.sleep(_CPU_BUSY_FALLBACK_SLEEP)
    now2 = time.monotonic()
    second = _read_proc_stat_cpu_totals()
    if second is None:
        with _CPU_BUSY_LOCK:
            _CPU_BUSY_PREV_SAMPLE = (total, idle, now)
        return None
    total2, idle2 = second

    with _CPU_BUSY_LOCK:
        _CPU_BUSY_PREV_SAMPLE = (total2, idle2, now2)

    total_delta = total2 - total
    idle_delta = idle2 - idle
    if total_delta <= 0:
        return None
    busy_delta = total_delta - idle_delta
    pct = (busy_delta / total_delta) * 100.0
    return round(max(0.0, min(100.0, pct)), 1)


def get_raspberry_pi_model() -> str:
    """Return the Raspberry Pi model string, or "unknown" if unavailable."""
    try:
        raw = RPI_MODEL_FILE.read_bytes()
        model = raw.replace(b"\x00", b"").decode("utf-8", errors="ignore").strip()
        return model or "unknown"
    except Exception:
        return "unknown"


# ---------------------------------------------------------------------------
# Hardware performance classification (audio-path SRC tier selection)
# ---------------------------------------------------------------------------
#
# Coupling note: the monitor's own flag-absent SRC-tier auto-detect keys on
# CPU part IDs read from /proc/cpuinfo (Cortex-A72/A76 vs A53-class), not on
# this model string. The two tables classify the same hardware split by
# different signals and must agree in effect: Pi 4/400/CM4 and Pi 5/500/CM5
# are Cortex-A72/A76 respectively; everything this table classifies False
# (Zero 2 W, Pi 3, unknown/unreadable) is Cortex-A53-class or unrecognised.
_HIGH_PERFORMANCE_MODEL_MARKERS = (
    "raspberry pi 4",
    "raspberry pi 400",
    "raspberry pi compute module 4",
    "raspberry pi 5",
    "raspberry pi 500",
    "raspberry pi compute module 5",
)


def classify_high_performance_pi(model: str) -> bool:
    """Pure classifier: True for a Pi 4/400/CM4/5/500/CM5-class model string.

    Matches by substring against the model text (case-insensitive) rather
    than exact equality, since the device-tree string carries extra detail
    (e.g. "Raspberry Pi 4 Model B Rev 1.4"). Anything not matching one of
    the allowlisted markers -- including "unknown" -- classifies False.
    """
    text = str(model or "").strip().lower()
    return any(marker in text for marker in _HIGH_PERFORMANCE_MODEL_MARKERS)


def is_high_performance_pi() -> bool:
    """Return True on Pi 4/400/CM4/Pi 5/500/CM5-class hardware, else False.

    Drives the audio-path Best-quality gate: that tier is filtered from
    the Web UI, rejected server-side, and demoted on smaller hardware
    (Zero 2 W, Pi 3, unknown) because it is unaffordable there. See
    classify_high_performance_pi() for the pure matching logic.
    """
    return classify_high_performance_pi(get_raspberry_pi_model())


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
