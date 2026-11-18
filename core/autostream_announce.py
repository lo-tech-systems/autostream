"""autostream_announce.py

The _autostream-playing._tcp mDNS announcement: the appliance advertises on the
LAN while a playback session is active (live input or repeat replay), so its
neighbours can tell it is in use.

sync_playing_announcement() is idempotent and thread-safe: it writes the avahi
service file when a session is active and the service is not yet announced, and
removes it when no session is active and the service is announced. The flag is
set only after a successful admin call, so a failed call is retried by the next
sync (each coordinator cycle, and a once-a-minute reconciliation thread).
"""
from __future__ import annotations

import threading
import time
from pathlib import Path
from typing import Callable, Optional

from autostream_rpi import get_appliance_id
from autostream_sysutils import remove_avahi_playing_service, write_avahi_playing_service

_AVAHI_PLAYING_PATH = Path("/etc/avahi/services/autostream-playing.service")
_playing_lock = threading.Lock()
_playing_announced: bool = False
_reconcile_started: bool = False
# Release string the coordinator passes to sync_playing_announcement; set by
# run_autostream so an API-thread caller can announce without knowing it.
# None until the coordinator has started.
_playing_version: Optional[str] = None


def set_version(version: Optional[str]) -> None:
    """Record the release string an API-thread caller announces with."""
    global _playing_version
    _playing_version = version


def reset_at_startup() -> None:
    """Remove any stale playing announcement from a previous crash, then sync
    _playing_announced to filesystem truth so sync_playing_announcement does
    not attempt a redundant remove on the first poll."""
    global _playing_announced
    remove_avahi_playing_service()
    _playing_announced = _AVAHI_PLAYING_PATH.exists()


def sync_playing_announcement(active: bool, version: str) -> None:
    """Idempotently sync the _autostream-playing._tcp mDNS announcement.

    *active* is the unified playback-session flag (live input or repeat
    replay): writes the avahi service file when a session is active and the
    service is not yet announced; removes it when no session is active and the
    service is currently announced. Updates _playing_announced only after a
    successful admin call. Thread-safe; never raises.
    """
    global _playing_announced
    active = bool(active)
    with _playing_lock:
        if active and not _playing_announced:
            if write_avahi_playing_service(version, get_appliance_id()):
                _playing_announced = True
        elif not active and _playing_announced:
            if remove_avahi_playing_service():
                _playing_announced = False


def _start_playing_reconciliation(version: str, session_active: Callable[[], bool]) -> None:
    """Start a daemon thread that periodically re-syncs the playing announcement.

    Recovers from transient admin failures by re-driving the idempotent sync
    from the current session state each tick.
    """
    def _reconcile() -> None:
        while True:
            time.sleep(60)
            sync_playing_announcement(session_active(), version)

    threading.Thread(target=_reconcile, daemon=True, name="playing-reconcile").start()


def start_reconciliation_once(version: str, session_active: Callable[[], bool]) -> None:
    """Start the reconciliation thread unless this process already has one."""
    global _reconcile_started
    if not _reconcile_started:
        _start_playing_reconciliation(version, session_active)
        _reconcile_started = True


def reset_for_tests() -> None:
    """Back to the start-up state: nothing announced, no version, no thread."""
    global _playing_announced, _playing_version, _reconcile_started
    _playing_announced = False
    _playing_version = None
    _reconcile_started = False
