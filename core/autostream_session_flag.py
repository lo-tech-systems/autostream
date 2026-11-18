"""autostream_session_flag.py

The playback-session flag: a plain file that exists while a playback session
is active (live input or repeat replay). The updater reads it to skip an
automatic update while the appliance is in use.

sync() is idempotent and thread-safe: it creates the file when a session is
active and removes it when none is, and touches the file system only on a
transition. A failed write or removal is retried by the next sync, which the
coordinator makes every cycle.
"""
from __future__ import annotations

import logging
import threading
from pathlib import Path

# /run/autostream-pipes is owned by the autostream user from boot, so no
# privileged call is needed. A reboot clears it.
SESSION_FLAG_PATH = Path("/run/autostream-pipes/session-active")

_lock = threading.Lock()
_present: bool = False


def reset_at_startup() -> None:
    """Remove a flag left by a crash of the previous process."""
    global _present
    with _lock:
        try:
            SESSION_FLAG_PATH.unlink(missing_ok=True)
            _present = False
        except OSError:
            logging.debug("session flag: stale flag not removed", exc_info=True)
            _present = True


def sync(active: bool) -> None:
    """Make the flag file match *active*. Never raises."""
    global _present
    active = bool(active)
    with _lock:
        if active == _present:
            return
        try:
            if active:
                SESSION_FLAG_PATH.touch()
            else:
                SESSION_FLAG_PATH.unlink(missing_ok=True)
            _present = active
        except OSError:
            logging.debug("session flag: could not %s the flag",
                          "write" if active else "remove", exc_info=True)


def reset_for_tests() -> None:
    """Back to the start-up state: no flag recorded as present."""
    global _present
    _present = False
