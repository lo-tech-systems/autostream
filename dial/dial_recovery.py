"""dial_recovery.py -- PIN recovery from start to finish.

Three pieces make up the recovery of a lost PIN:

  - the request file the appliance writes when an admin asks for recovery;
  - the running marker, created at every start and removed on a clean stop,
    whose survival shows a real power cycle;
  - the rule that arms recovery at startup only when both line up, with a
    clock-sync-aware age check on the request that fails open by design.

Once armed, a 10-minute window opens in which the PIN can be replaced from
the appliance, provided a person confirms at the dial (by turning the volume
knob or touching the screen).  The window is announced over mDNS while it is
open, so the appliance can offer the reset.

begin_run and end_run run on the main thread at startup and shutdown.  The
window is touched by three threads: startup opens it, a timer closes it, and
the management handlers read it and complete it.  Its own lock guards its
state; the announce callback always runs outside that lock.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

import logging
import threading
import time
from pathlib import Path
from typing import Callable

from dial_config import PIN_RESET_PATH, RUNNING_MARKER_PATH


class RecoveryWindow:
    """10-minute PIN recovery window opened at startup when a PIN is set.

    State machine:
      open()          → _active=True,  _volume_confirmed=False, starts timer
      confirm_volume()→ _volume_confirmed=True (only while active)
      _expire()       → timer fires: _active=False, announce without pin_recovery
      complete()      → PIN replaced: cancel timer, _active=False, announce
    """

    _WINDOW_S = 600

    def __init__(self, on_announce: Callable[[bool], None]) -> None:
        self._on_announce      = on_announce
        self._lock             = threading.Lock()
        self._active           = False
        self._volume_confirmed = False
        self._opened_monotonic: float | None = None
        self._timer: threading.Timer | None = None

    def open(self) -> None:
        with self._lock:
            self._volume_confirmed = False
            self._active = True
            self._opened_monotonic = time.monotonic()
            timer = threading.Timer(self._WINDOW_S, self._expire)
            timer.daemon = True
            self._timer = timer
        timer.start()
        self._on_announce(True)   # outside lock — slow subprocess
        logging.info("PIN recovery window opened (10 min)")

    def _expire(self) -> None:
        with self._lock:
            self._active = False
        self._on_announce(False)  # outside lock
        logging.info("PIN recovery window expired")

    def complete(self) -> None:
        with self._lock:
            timer = self._timer
            self._timer = None
            self._active = False
        if timer:
            timer.cancel()
        self._on_announce(False)  # outside lock
        logging.info("PIN recovery: PIN updated")

    def confirm_volume(self) -> None:
        with self._lock:
            if not (self._active and not self._volume_confirmed):
                return
            self._volume_confirmed = True
        logging.info("PIN recovery: volume confirmed")

    def snapshot(self) -> dict:
        """Return a thread-safe copy of current recovery window state,
        including recovery_remaining_ms — milliseconds left in the 10-minute
        window, clamped at 0 (0 whenever the window is not active)."""
        with self._lock:
            remaining_ms = 0
            if self._active and self._opened_monotonic is not None:
                elapsed_ms = int((time.monotonic() - self._opened_monotonic) * 1000)
                remaining_ms = max(0, self._WINDOW_S * 1000 - elapsed_ms)
            return {
                "active": self._active,
                "volume_confirmed": self._volume_confirmed,
                "recovery_remaining_ms": remaining_ms,
            }


# ---- Running marker and PIN-recovery arming ---------------------------------

def _check_unclean_shutdown() -> bool:
    """Log a WARNING if the running marker survived from a previous run,
    and return whether it did.

    Its survival means the previous stop did NOT go through the clean-
    shutdown path in main()'s finally block — most likely a power loss, or
    the process being killed outright. The return value is also the
    "genuinely power-cycled" half of the PIN-recovery arming decision below:
    a service restart that went through clean shutdown must not be treated
    as evidence of physical presence at the device.

    Must be called BEFORE _create_running_marker() recreates the file, or
    the check would always see the marker this very process just wrote and
    "detect" an unclean shutdown on every start.
    """
    survived = RUNNING_MARKER_PATH.exists()
    if survived:
        logging.warning(
            "autostream-dial: running marker survived from the previous "
            "run — last shutdown was not clean (power loss or the process "
            "was killed)"
        )
    return survived


def _create_running_marker() -> None:
    """Create the running marker for this run.

    Wrapped in try/except: a dial with a read-only or otherwise broken state
    directory must still be able to start. Losing this signal only degrades
    unclean-shutdown detection, it must never take the service down.
    """
    try:
        RUNNING_MARKER_PATH.touch(exist_ok=True)
    except OSError as e:
        logging.warning(
            "autostream-dial: could not create running marker %s: %s",
            RUNNING_MARKER_PATH, e,
        )


def end_run() -> None:
    """Delete the running marker as part of a clean shutdown.

    Wrapped in try/except: a failure here must never prevent the rest of
    the shutdown sequence (in main()'s finally block) from completing.
    """
    try:
        RUNNING_MARKER_PATH.unlink(missing_ok=True)
    except OSError as e:
        logging.warning(
            "autostream-dial: could not remove running marker %s: %s",
            RUNNING_MARKER_PATH, e,
        )


# ---- PIN-recovery arming decision ------------------------------------------
#
# A PIN-recovery request is only ever armed on startup, and only when BOTH
# the running marker survived (the previous stop was not clean — see
# _check_unclean_shutdown above) AND a request file is present. Neither
# alone is enough: a survived marker with no request means an ordinary power
# cycle nobody asked for, and a request with a clean-shutdown marker means a
# restart happened before the device was ever power-cycled (a
# reconfiguration restart, or a plain `reboot`) — the request must stay
# armed for a real power cycle later, not fire on the restart itself.

_TIMESYNC_MARKER_PATH = Path('/run/systemd/timesync/synchronized')
_RECOVERY_REQUEST_MAX_AGE_S = 30 * 60
_TIMESYNC_POLL_TIMEOUT_S = 30
_TIMESYNC_POLL_INTERVAL_S = 1


def _recovery_request_within_window(
    request_path: Path,
    *,
    sync_marker_path: Path,
    now: Callable[[], float] = time.time,
    sleep: Callable[[float], None] = time.sleep,
) -> bool:
    """Return whether a pending PIN-recovery request is still within its
    30-minute window, measured from *request_path*'s mtime.

    This hardware has no RTC. systemd-timesyncd restores the last known
    time from disk at boot, so the clock starts plausible but can easily sit
    slightly BEHIND a file written after that save — an age comparison
    against it would be meaningless, or even negative, until NTP finishes.
    Comparing dates cannot detect this; timesyncd instead publishes the fact
    directly by creating *sync_marker_path* only once the clock has actually
    synchronised. Being tmpfs, that marker is absent at every boot, so its
    absence here is a real "not yet synced" signal, not a stale leftover.

    If the marker is not there yet, this polls for it briefly rather than
    trusting an unsynced clock immediately — but only because a request is
    actually pending; a normal boot with no request never reaches this
    function at all, so it is never delayed by this wait.

    If the clock still has not synchronised after the poll times out, the
    request is honoured anyway and the skipped check is logged. This is
    deliberate, not an oversight: a dial with broken time sync and a lost
    PIN would otherwise be permanently unrecoverable. The rest of the
    arming chain — an explicit request plus physical presence at the device
    afterwards — is still intact; the clock is simply the least trustworthy
    input in that chain, so it is the one that yields. Resist the urge to
    "fix" this into a fail-closed check; that trade was made on purpose.
    """
    if not sync_marker_path.exists():
        waited = 0.0
        while waited < _TIMESYNC_POLL_TIMEOUT_S:
            sleep(_TIMESYNC_POLL_INTERVAL_S)
            waited += _TIMESYNC_POLL_INTERVAL_S
            if sync_marker_path.exists():
                break
        if not sync_marker_path.exists():
            logging.warning(
                "autostream-dial: clock not yet synchronised after waiting "
                "%ds — honouring the pending PIN recovery request without "
                "checking its age",
                _TIMESYNC_POLL_TIMEOUT_S,
            )
            return True

    try:
        age_s = now() - request_path.stat().st_mtime
    except OSError:
        # The file existed moments ago (the caller only reaches this
        # function when it does) but disappeared under us — treat that the
        # same as an expired request rather than raising out of startup.
        return False
    return age_s <= _RECOVERY_REQUEST_MAX_AGE_S


def _clear_recovery_request() -> None:
    """Delete a consumed PIN-recovery request file.

    Best-effort like the running-marker helpers above: a failure here must
    never prevent the service from starting, and by the time this runs the
    request has already been acted on (armed, or correctly left unarmed).
    """
    try:
        PIN_RESET_PATH.unlink(missing_ok=True)
    except OSError as e:
        logging.warning(
            "autostream-dial: could not remove PIN recovery request %s: %s",
            PIN_RESET_PATH, e,
        )


def begin_run(pin: str) -> bool:
    """Start-of-run bookkeeping: decide whether PIN recovery is armed, then
    create the running marker. Returns whether recovery is armed."""
    # Check BEFORE recreating: recreating first would make the marker
    # "survive" every single start, including this one. Likewise the
    # request file is read here, before anything below can touch it.
    running_marker_survived = _check_unclean_shutdown()
    recovery_request_present = PIN_RESET_PATH.exists()

    # Arm only when both signals line up: a survived marker (genuine power
    # cycle) AND a pending request (someone asked). The request file is
    # deleted only in this branch — an admin who arms recovery and then hits
    # an unrelated clean restart before power-cycling must find the arm
    # still intact, not silently cleared.
    recovery_armed = False
    if running_marker_survived and recovery_request_present:
        if pin:
            recovery_armed = _recovery_request_within_window(
                PIN_RESET_PATH, sync_marker_path=_TIMESYNC_MARKER_PATH,
            )
        # else: a request with no PIN configured has nothing to recover —
        # fall through to the deletion below without evaluating its age.
        _clear_recovery_request()

    _create_running_marker()
    return recovery_armed
