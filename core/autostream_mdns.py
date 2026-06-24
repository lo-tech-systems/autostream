"""autostream_mdns.py — Shared Avahi mDNS browsing and registry scaffolding.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.

This module owns only transport and registry mechanics:
  - launching avahi-browse --no-fail -p -r <service-type>
  - reading its line-oriented output
  - parsing Avahi fields and quoted TXT records with shlex
  - IPv4 filtering
  - tracking the Avahi five-tuple (interface, protocol, service_name, type, domain)
  - deduplicating multiple interfaces via a caller-supplied identity key
  - thread-safe snapshots
  - add, update and remove event handling
  - clearing stale state after an unexpected avahi-browse exit
  - orderly shutdown: stopping the subprocess and the browser thread cleanly
  - retrying with per-browser exponential delays: 5, 10, 20, 30 seconds
  - resetting the retry delay after a valid event or 60 seconds of uptime
  - idempotent daemon-thread startup
  - concise, rate-limited logging

This module must not know about dial authorization, dial persistence,
playing-state capabilities, appliance UI behavior, configuration files or HTTP
forwarding.  Each consumer supplies a parse_fn that converts a resolved Avahi
event into its domain model and returns (identity_key, model) or None to skip.
"""
from __future__ import annotations

import logging
import shlex
import subprocess
import threading
import time
from typing import Any, Callable, Dict, Generic, List, Optional, Tuple, TypeVar

_T = TypeVar("_T")

logger = logging.getLogger(__name__)

# Retry delay sequence for avahi-browse restarts (seconds)
_RETRY_DELAYS = [5, 10, 20, 30]
# Delay resets to the first value after this many seconds of uptime
_UPTIME_RESET_SECS = 60


def parse_avahi_txt(raw: str) -> dict[str, str]:
    """Parse an Avahi TXT record string into {key: value} using shlex."""
    result: dict[str, str] = {}
    try:
        for token in shlex.split(raw):
            if "=" in token:
                k, _, v = token.partition("=")
                result[k] = v
    except ValueError as e:
        logger.debug("TXT parse error (malformed quoted string): %s", e)
    return result


class MdnsBrowser(Generic[_T]):
    """Generic Avahi browser that maintains a deduped, identity-keyed registry.

    Parameters
    ----------
    service_type:
        The mDNS service type to browse, e.g. ``_autostream-dial._tcp``.
    parse_fn:
        Called for each resolved (=) IPv4 event.  Receives:
          - ``parts``: the semicolon-split Avahi output fields (list[str])
          - ``txt``: parsed TXT key/value dict
        Returns ``(identity_key, model)`` to register the entry, or ``None``
        to ignore it.
    on_add:
        Optional callback called when a new identity_key appears.
        Invoked outside the registry lock.
    on_remove:
        Optional callback called when an identity_key is fully removed.
        Invoked outside the registry lock.  Must not perform network I/O.
    """

    def __init__(
        self,
        service_type: str,
        parse_fn: Callable[[List[str], Dict[str, str]], Optional[Tuple[Any, _T]]],
        on_add: Optional[Callable[[Any, _T], None]] = None,
        on_remove: Optional[Callable[[Any, _T], None]] = None,
        on_change: Optional[Callable[[Any, _T, _T], None]] = None,
    ) -> None:
        self._service_type = service_type
        self._parse_fn = parse_fn
        self._on_add = on_add
        self._on_remove = on_remove
        self._on_change = on_change

        # Registry lock — guards _by_key, _by_identity, _has_browse_event,
        # _started, and _start_monotonic.
        self._lock = threading.Lock()
        # Five-tuple key → (identity_key, model)
        self._by_key: dict[tuple, tuple[Any, _T]] = {}
        # identity_key → model (most-recently-seen sighting wins)
        self._by_identity: dict[Any, _T] = {}

        self._started = False
        self._start_monotonic: float = 0.0
        self._has_browse_event: bool = False

        # Lifecycle state
        self._stop_event = threading.Event()
        self._app_shutdown: Optional[threading.Event] = None
        # Lifecycle/process lock — guards _current_proc and _browse_thread.
        # Never held while calling terminate(), wait(), kill(), or join().
        self._proc_lock = threading.Lock()
        self._current_proc: Optional[subprocess.Popen] = None
        self._browse_thread: Optional[threading.Thread] = None

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def start(self, shutdown_event: Optional[threading.Event] = None) -> None:
        """Start the background browse thread.

        Idempotent; safe to call multiple times.  Accepts an optional
        application-level shutdown event; when that event (or the browser's own
        stop event) is set the browse loop exits cleanly without retrying.
        """
        with self._lock:
            if self._started:
                return
            if self._stop_event.is_set():
                return
            if shutdown_event is not None and shutdown_event.is_set():
                return
            self._app_shutdown = shutdown_event
            self._started = True
            self._start_monotonic = time.monotonic()

        t = threading.Thread(
            target=self._browse_loop,
            daemon=True,
            name=f"mdns-{self._service_type}",
        )
        t.start()
        with self._proc_lock:
            self._browse_thread = t

    def stop(self, timeout: float = 2.0) -> None:
        """Stop the browse loop and terminate any running avahi-browse child.

        Idempotent.  Safe to call before start(), during active browsing,
        during retry backoff, and after a previous stop().  Never blocks
        indefinitely.  Clears the in-memory registry without firing callbacks.
        """
        self._stop_event.set()

        with self._proc_lock:
            proc = self._current_proc
            thread = self._browse_thread

        deadline = time.monotonic() + timeout

        if proc is not None:
            try:
                proc.terminate()
            except OSError:
                pass
            graceful = min(0.5, max(0.0, (deadline - time.monotonic()) / 2))
            try:
                proc.wait(timeout=graceful)
            except subprocess.TimeoutExpired:
                try:
                    proc.kill()
                except OSError:
                    pass
                try:
                    proc.wait(timeout=max(0.0, deadline - time.monotonic()))
                except (subprocess.TimeoutExpired, Exception):
                    pass
            except Exception:
                pass

        if thread is not None:
            remaining = max(0.0, deadline - time.monotonic())
            thread.join(timeout=remaining)

        self._clear_registry()

    def get_snapshot(self) -> dict[Any, _T]:
        """Return an immutable shallow copy of the current identity → model mapping."""
        with self._lock:
            return dict(self._by_identity)

    @property
    def has_started(self) -> bool:
        with self._lock:
            return self._started

    @property
    def has_browse_event(self) -> bool:
        """True after at least one Avahi event has been processed."""
        with self._lock:
            return self._has_browse_event

    @property
    def start_monotonic(self) -> float:
        with self._lock:
            return self._start_monotonic

    def scanner_ready(self) -> bool:
        """True when the scanner has processed at least one event or 8s have elapsed."""
        with self._lock:
            if self._has_browse_event:
                return True
            if not self._started:
                return False
            return (time.monotonic() - self._start_monotonic) >= 8.0

    def grace_remaining_ms(self) -> int:
        """Milliseconds remaining in the 8-second startup discovery grace period."""
        with self._lock:
            if self._has_browse_event or not self._started:
                return 0
            elapsed_ms = int((time.monotonic() - self._start_monotonic) * 1000)
            return max(0, 8000 - elapsed_ms)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _shutdown_requested(self) -> bool:
        """Return True when either the internal stop event or the application event is set."""
        if self._stop_event.is_set():
            return True
        app = self._app_shutdown
        if app is not None and app.is_set():
            return True
        return False

    def _clear_registry(self) -> None:
        """Clear _by_key and _by_identity under the registry lock without callbacks."""
        with self._lock:
            self._by_key.clear()
            self._by_identity.clear()

    def _interruptible_wait(self, delay: float) -> None:
        """Wait up to *delay* seconds, returning early if shutdown is requested.

        Shutdown responsiveness is at most 100 ms.
        """
        deadline = time.monotonic() + delay
        while True:
            if self._shutdown_requested():
                return
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return
            self._stop_event.wait(timeout=min(0.1, remaining))

    # ------------------------------------------------------------------
    # Browse loop
    # ------------------------------------------------------------------

    def _browse_loop(self) -> None:
        delay_idx = 0

        while True:
            if self._shutdown_requested():
                return

            self._clear_registry()

            if self._shutdown_requested():
                return

            run_start = time.monotonic()
            had_valid_event = False
            rc = None
            proc = None

            try:
                proc = subprocess.Popen(
                    ["avahi-browse", "--no-fail", "-p", "-r", self._service_type],
                    stdout=subprocess.PIPE,
                    text=True,
                )

                # Publish the child under proc_lock then immediately re-check
                # shutdown so stop() cannot miss it.
                with self._proc_lock:
                    self._current_proc = proc

                if self._shutdown_requested():
                    try:
                        proc.terminate()
                        proc.wait(timeout=1.0)
                    except Exception:
                        pass
                    with self._proc_lock:
                        if self._current_proc is proc:
                            self._current_proc = None
                    return

                for line in proc.stdout:
                    had_valid_event = True
                    with self._lock:
                        self._has_browse_event = True
                    self._handle_line(line.strip())

                    if self._shutdown_requested():
                        break

                    if (time.monotonic() - run_start) >= _UPTIME_RESET_SECS:
                        delay_idx = 0

                # Reap to populate returncode without blocking.
                try:
                    proc.wait(timeout=0)
                except subprocess.TimeoutExpired:
                    pass
                rc = proc.returncode

            except Exception as exc:
                if not self._shutdown_requested():
                    logger.warning("mdns(%s): %s", self._service_type, exc)

            finally:
                with self._proc_lock:
                    if proc is not None and self._current_proc is proc:
                        self._current_proc = None

            if self._shutdown_requested():
                return

            logger.warning(
                "mdns(%s): avahi-browse exited rc=%s; restarting",
                self._service_type, rc,
            )

            # Clear stale state before the retry wait.
            self._clear_registry()

            if had_valid_event:
                delay_idx = 0

            delay = _RETRY_DELAYS[min(delay_idx, len(_RETRY_DELAYS) - 1)]
            delay_idx = min(delay_idx + 1, len(_RETRY_DELAYS) - 1)
            self._interruptible_wait(delay)

    def _handle_line(self, line: str) -> None:
        parts = line.split(";")
        if not parts:
            return
        event = parts[0]

        if event == "=" and len(parts) >= 10 and parts[2] == "IPv4":
            five_tuple = tuple(parts[1:6])
            txt = parse_avahi_txt(parts[9])
            parsed = self._parse_fn(parts, txt)
            if parsed is None:
                return
            identity_key, model = parsed

            added = False
            with self._lock:
                old = self._by_identity.get(identity_key)
                self._by_key[five_tuple] = (identity_key, model)
                self._by_identity[identity_key] = model
                if old is None:
                    added = True

            if added and self._on_add:
                try:
                    self._on_add(identity_key, model)
                except Exception:
                    logger.debug(
                        "mdns(%s): on_add callback raised", self._service_type, exc_info=True
                    )

        elif event == "-" and len(parts) >= 6 and parts[2] == "IPv4":
            five_tuple = tuple(parts[1:6])
            removed_key = None
            removed_model = None
            changed_key = None
            changed_removed = None
            changed_remaining = None

            with self._lock:
                entry = self._by_key.pop(five_tuple, None)
                if entry is not None:
                    identity_key, popped_model = entry
                    # Check if another five-tuple still holds this identity
                    remaining = next(
                        (m for k, (ik, m) in self._by_key.items() if ik == identity_key),
                        None,
                    )
                    if remaining is not None:
                        self._by_identity[identity_key] = remaining
                        changed_key = identity_key
                        changed_removed = popped_model
                        changed_remaining = remaining
                    else:
                        removed_model = self._by_identity.pop(identity_key, None)
                        removed_key = identity_key

            if removed_key is not None and self._on_remove:
                try:
                    self._on_remove(removed_key, removed_model)
                except Exception:
                    logger.debug(
                        "mdns(%s): on_remove callback raised", self._service_type, exc_info=True
                    )

            if changed_key is not None and self._on_change:
                try:
                    self._on_change(changed_key, changed_removed, changed_remaining)
                except Exception:
                    logger.debug(
                        "mdns(%s): on_change callback raised", self._service_type, exc_info=True
                    )
