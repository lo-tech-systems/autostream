"""autostream_appliance_identity.py

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.

Appliance / Dial identity derivation: a stable public identifier for each,
derived from the CPU serial number by one-way hashing (namespaced SHA-256,
truncated to 20 lowercase hex chars), with a persistent-file fallback when
the serial is unavailable. The raw CPU serial is never stored or returned;
only the derived hash is exposed.

Split out of ``core/autostream_rpi.py``, which re-exports these names for
existing importers. This is security-relevant (serial hashing), so the
move is byte-for-byte -- no edits beyond adjusting the import of
``get_cpu_serial`` to its new home in ``autostream_system_stats.py``.
"""

from __future__ import annotations

import hashlib
import logging
import re
import threading
from pathlib import Path
from typing import Optional

from autostream_system_stats import get_cpu_serial

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Appliance identity constants
# ---------------------------------------------------------------------------

_APPLIANCE_NAMESPACE = "autostream-appliance-v1:"
_DIAL_NAMESPACE = "autostream-dial-v1:"
_HEX_RE = re.compile(r"^[0-9a-f]+$")

APPLIANCE_ID_FILE = Path("/var/lib/autostream/appliance-id")
DIAL_ID_FILE = Path("/var/lib/autostream/dial-id")

_ID_CACHE_LOCK = threading.Lock()
_appliance_id_cache: Optional[str] = None
_appliance_id_cache_set: bool = False
_appliance_id_error_logged: bool = False
_dial_id_cache: Optional[str] = None
_dial_id_cache_set: bool = False
_dial_id_error_logged: bool = False


def _namespaced_id_hash(namespace: str, cpu_serial: str) -> Optional[str]:
    """Return the first 20 lowercase hex chars of SHA-256(namespace + normalized_serial).

    Returns None if the serial is empty or not pure hexadecimal after normalization.
    The raw CPU serial is never stored or returned; only the derived hash is exposed.
    """
    normalized = cpu_serial.strip().lower()
    if not normalized or not _HEX_RE.match(normalized):
        return None
    digest = hashlib.sha256((namespace + normalized).encode("utf-8")).hexdigest()
    return digest[:20]


def _read_id_file(path: Path) -> Optional[str]:
    """Read a 20-char lowercase hex identity from a fallback file.

    Returns the value if valid, None otherwise. Never creates or modifies the file.
    """
    try:
        raw = path.read_text(encoding="utf-8").strip()
    except FileNotFoundError:
        return None
    except Exception:
        return None
    if len(raw) == 20 and _HEX_RE.match(raw):
        return raw
    return None


def get_appliance_id() -> Optional[str]:
    """Return the stable public appliance identity (20 lowercase hex chars).

    Derived from the CPU serial hash, or read from the persistent fallback
    file if the serial is unavailable.  Caches the result for the process
    lifetime.  Returns None and logs one error per process if both sources
    fail.  Never raises during normal operation.
    """
    global _appliance_id_cache, _appliance_id_cache_set, _appliance_id_error_logged

    with _ID_CACHE_LOCK:
        if _appliance_id_cache_set:
            return _appliance_id_cache

        # Primary: CPU serial hash
        serial = get_cpu_serial()
        derived = _namespaced_id_hash(_APPLIANCE_NAMESPACE, serial)
        if derived:
            _appliance_id_cache = derived
            _appliance_id_cache_set = True
            return _appliance_id_cache

        # Fallback: persistent file written by the installer
        fallback = _read_id_file(APPLIANCE_ID_FILE)
        if fallback:
            _appliance_id_cache = fallback
            _appliance_id_cache_set = True
            return _appliance_id_cache

        # Both sources unavailable
        _appliance_id_cache = None
        _appliance_id_cache_set = True
        if not _appliance_id_error_logged:
            _appliance_id_error_logged = True
            logger.error(
                "Appliance identity unavailable: CPU serial is absent or non-hex and "
                "%s is missing or invalid. Multi-appliance features are disabled.",
                APPLIANCE_ID_FILE,
            )
        return None


def get_dial_id() -> Optional[str]:
    """Return the stable public Dial identity (20 lowercase hex chars).

    Uses the same normalization and hashing as get_appliance_id() but with a
    distinct namespace, so the same hardware produces different appliance and
    dial identifiers.  Caches the result for the process lifetime.  Returns
    None and logs one error per process if both sources fail.
    """
    global _dial_id_cache, _dial_id_cache_set, _dial_id_error_logged

    with _ID_CACHE_LOCK:
        if _dial_id_cache_set:
            return _dial_id_cache

        serial = get_cpu_serial()
        derived = _namespaced_id_hash(_DIAL_NAMESPACE, serial)
        if derived:
            _dial_id_cache = derived
            _dial_id_cache_set = True
            return _dial_id_cache

        fallback = _read_id_file(DIAL_ID_FILE)
        if fallback:
            _dial_id_cache = fallback
            _dial_id_cache_set = True
            return _dial_id_cache

        _dial_id_cache = None
        _dial_id_cache_set = True
        if not _dial_id_error_logged:
            _dial_id_error_logged = True
            logger.error(
                "Dial identity unavailable: CPU serial is absent or non-hex and "
                "%s is missing or invalid.",
                DIAL_ID_FILE,
            )
        return None
