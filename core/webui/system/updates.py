#!/usr/bin/env python3
"""webui/system/updates.py

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.

The installed application version, read once through the privileged helper.
"""

from __future__ import annotations

import json
import subprocess
import threading
from typing import Optional

# Cached on first call; immutable for the process lifetime since an update
# always triggers a full process restart.
_app_version_cache: Optional[str] = None

# A leaf lock: the start-up announcement and the web server's prime may both
# ask at once; they share one helper call.
_app_version_lock = threading.Lock()


def get_app_version() -> str:
    """Return the installed application version via the privileged helper.

    The result is cached in memory after the first call. Because applying an
    update always restarts the process, the version cannot change while the
    process is running.  Every failed helper outcome (exception, nonzero exit,
    invalid JSON, blank tag) is cached as "unknown" so repeated calls cannot
    each incur the five-second subprocess timeout.
    """
    with _app_version_lock:
        return _get_app_version_locked()


def _get_app_version_locked() -> str:
    global _app_version_cache
    if _app_version_cache is not None:
        return _app_version_cache

    cmd = [
        "/usr/bin/sudo",
        "-n",
        "/usr/local/libexec/autostream/autostream_admin",
        "version-info",
    ]
    try:
        p = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=5,
            check=False,
        )
    except Exception:
        _app_version_cache = "unknown"
        return _app_version_cache

    if p.returncode != 0:
        _app_version_cache = "unknown"
        return _app_version_cache

    try:
        payload = json.loads(p.stdout or "{}")
    except Exception:
        _app_version_cache = "unknown"
        return _app_version_cache

    version = str(payload.get("release_tag") or "").strip()
    _app_version_cache = version or "unknown"
    return _app_version_cache
