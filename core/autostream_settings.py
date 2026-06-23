#!/usr/bin/env python3
"""autostream_settings.py

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.

In-memory settings store for the autostream main-appliance process.

One SettingsStore is created at process startup and shared between the
coordinator (autostream_core) and the Web UI (autostream_webui / WebUIState).
It is the sole authoritative owner of the main configuration during process
operation.  The background save thread writes dirty changes to disk every five
seconds.  Synchronous save_now() is available for durability-sensitive
operations such as first-boot Finish and reboot.

Lock order — never hold the SettingsStore._lock while:
  - performing disk I/O (use CONFIG_IO_LOCK through save_config instead)
  - calling run_admin_cmd()
  - calling OwnTone APIs
  - connecting to the monitor daemon
  - waiting for coordinator or restart completion
"""
from __future__ import annotations

import copy
import logging
import threading
from typing import Callable, Optional

from autostream_config import (
    AutostreamConfig,
    load_config,
    parse_config,
    save_config,
)

# Default interval for the background dirty-save cycle.
SETTINGS_SAVE_INTERVAL_SECONDS = 5.0


class SettingsStore:
    """Canonical in-memory raw configuration and parsed snapshots.

    Provides:
    - snapshot() → AutostreamConfig: immutable parsed view of current settings
    - raw_snapshot() → dict: deep copy of raw JSON (for code needing unknown keys)
    - update(mutator) → AutostreamConfig: atomic field-level mutation
    - save_now() → bool: synchronous durability barrier
    - close(*, save=True): orderly shutdown
    - reload_from_disk(*, discard=False): explicit external-change handling

    Startup loads the raw JSON once.  Missing config is represented by {}
    plus parsed defaults; it is not an initialisation error.

    The background thread wakes every _save_interval_seconds.  If the store
    is dirty it copies the raw dict under the store lock, releases the lock,
    then writes via _writer (defaults to save_config).  On success it clears
    the dirty flag only if no newer mutation arrived during the write.  On
    failure it logs the error, leaves the store dirty, and retries next cycle.
    """

    def __init__(
        self,
        config_path: str,
        *,
        _save_interval_seconds: float = SETTINGS_SAVE_INTERVAL_SECONDS,
        _writer: Optional[Callable[[str, dict], None]] = None,
        _stop_event: Optional[threading.Event] = None,
    ) -> None:
        """Initialise the store and start the background save thread.

        Parameters
        ----------
        config_path:
            Path to the main autostream JSON configuration file.
        _save_interval_seconds:
            Interval between periodic save attempts.  Defaults to 5 s.
            Tests may pass a short value (e.g. 0.05) for fast operation.
        _writer:
            Persistence callable (path, data) → None.  Defaults to
            save_config from autostream_config.  Inject a stub in tests.
        _stop_event:
            External threading.Event to stop the background thread.
            If None, a private event is created.
        """
        self._config_path = config_path
        self._save_interval = float(_save_interval_seconds)
        self._writer: Callable[[str, dict], None] = _writer or save_config
        self._stop_event = _stop_event or threading.Event()

        # In-memory state — protected by _lock.
        self._lock = threading.Lock()
        self._raw: dict = {}
        self._dirty: bool = False
        # Monotonically increasing; used to detect mutations that arrive while
        # a save is in progress so that dirty state is not prematurely cleared.
        self._generation: int = 0
        # Serialises all disk writes (save_now threads and _run_save_cycle).
        # Ensures a timed-out save_now thread that eventually completes cannot
        # write stale data after a newer save cycle has already written.
        self._write_lock = threading.Lock()

        # Load initial raw config (errors become {} + parsed defaults).
        try:
            self._raw = load_config(config_path)
        except Exception:
            logging.warning(
                "Settings: could not load %s at startup; using defaults.",
                config_path,
                exc_info=True,
            )
            self._raw = {}

        # Start background save thread.
        self._thread: Optional[threading.Thread] = threading.Thread(
            target=self._save_worker,
            name="settings-save",
            daemon=True,
        )
        self._thread.start()

    # ── Read ─────────────────────────────────────────────────────────────────

    def snapshot(self) -> AutostreamConfig:
        """Return a fresh immutable parsed snapshot of the current settings.

        Each call produces a new AutostreamConfig from a deep copy of the
        canonical raw dict so that mutable nested structures (OwnTone offsets,
        track-ID provider settings) cannot affect canonical state.
        """
        with self._lock:
            raw_copy = copy.deepcopy(self._raw)
        return parse_config(raw_copy)

    def raw_snapshot(self) -> dict:
        """Return a deep copy of the canonical raw configuration dict.

        For use by code that genuinely needs to preserve unknown/raw keys
        (e.g. the atomic save path).  Callers must not retain a reference to
        the returned dict across subsequent mutations.
        """
        with self._lock:
            return copy.deepcopy(self._raw)

    @property
    def config_path(self) -> str:
        """The path to the configuration file managed by this store."""
        return self._config_path

    # ── Write ────────────────────────────────────────────────────────────────

    def update(self, mutator: Callable[[dict], None]) -> AutostreamConfig:
        """Apply *mutator* to a copy of the raw config, commit, and return a snapshot.

        The mutator receives a deep copy of the raw dict and may modify it in
        place.  If the mutator raises the canonical state is unchanged.  On
        success the canonical raw dict is replaced with the mutated copy, the
        generation counter is incremented, and the store is marked dirty.

        The lock is held for the duration of the deep copy, the mutator call,
        and the state update.  Mutators must be fast and must not perform I/O,
        OwnTone API calls, or other blocking operations.
        """
        with self._lock:
            raw_copy = copy.deepcopy(self._raw)
            mutator(raw_copy)          # raises → canonical state unchanged
            self._raw = raw_copy
            self._generation += 1
            self._dirty = True
        return self.snapshot()

    def save_now(self, timeout: float = 10.0) -> bool:
        """Synchronously write the current configuration to disk.

        Takes a safe copy under the store lock, releases the lock, then calls
        the persistence writer in a daemon thread so the call can time out.
        The thread holds _write_lock for the duration of the disk write, which
        serialises concurrent writes from _run_save_cycle: whichever holds the
        lock last writes last, so a timed-out thread that eventually finishes
        cannot overwrite a newer save that ran while it was stalled.
        Clears the dirty flag only when the generation at snapshot time matches
        the current generation (i.e. no new mutation arrived during the write).

        Returns True on success, False on failure or timeout.  Failures are
        logged; the in-memory value remains active and dirty for the next save
        cycle.
        """
        with self._lock:
            raw_copy = copy.deepcopy(self._raw)
            gen_at_start = self._generation

        _result: list[bool] = []
        _cancel = threading.Event()

        def _write() -> None:
            with self._write_lock:
                # Re-check generation after acquiring the write lock: a newer
                # save may have run while we were queued behind it.
                with self._lock:
                    if self._generation != gen_at_start:
                        return
                if _cancel.is_set():
                    return
                try:
                    self._writer(self._config_path, raw_copy)
                    _result.append(True)
                except Exception:
                    logging.error("Settings: save_now failed", exc_info=True)
                    _result.append(False)

        t = threading.Thread(target=_write, daemon=True)
        t.start()
        t.join(timeout)

        if t.is_alive():
            _cancel.set()
            logging.error("Settings: save_now timed out after %.1fs", timeout)
            return False

        if not _result or not _result[0]:
            return False

        with self._lock:
            if self._generation == gen_at_start:
                self._dirty = False
        return True

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def reload_from_disk(self, *, discard: bool = False) -> None:
        """Reload the raw configuration from disk.

        Must not be called during normal operation to pick up live Web UI
        changes; use the store's in-memory snapshot instead.  Appropriate at
        startup or after external writes (installer, recovery tools).

        Raises ValueError if the store is dirty and ``discard`` is False.
        Passes ``discard=True`` to replace dirty in-memory state with what is
        on disk (e.g. factory reset preparation).
        """
        with self._lock:
            if self._dirty and not discard:
                raise ValueError(
                    "Settings: cannot reload from disk while dirty; "
                    "call save_now() first or pass discard=True."
                )

        raw = load_config(self._config_path)

        with self._lock:
            self._raw = raw
            self._dirty = False
            self._generation += 1

    def close(self, *, save: bool = True) -> None:
        """Stop the background save thread and optionally make a final save.

        Safe to call multiple times; subsequent calls are no-ops after the
        thread exits.  Callers from the main process shutdown path should
        pass ``save=True`` (the default) to flush any dirty state.
        """
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=15.0)
            self._thread = None
        if save:
            with self._lock:
                is_dirty = self._dirty
            if is_dirty:
                self.save_now()

    # ── Background thread ────────────────────────────────────────────────────

    def _save_worker(self) -> None:
        """Background thread body: save config every interval when dirty."""
        while not self._stop_event.wait(self._save_interval):
            self._run_save_cycle()
        # Thread exits when stop event is set.  Final save is handled by close().

    def _run_save_cycle(self) -> None:
        """Attempt one dirty-save cycle; log and leave dirty on failure."""
        with self._lock:
            if not self._dirty:
                return
            raw_copy = copy.deepcopy(self._raw)
            gen_at_start = self._generation
        # _lock released before acquiring _write_lock to avoid inversion with
        # the lock order used inside save_now's _write thread.

        with self._write_lock:
            # Re-check after queuing: a save_now thread may have written the
            # same generation while we were waiting for the write lock.
            with self._lock:
                if not self._dirty or self._generation != gen_at_start:
                    return

            try:
                self._writer(self._config_path, raw_copy)
            except Exception:
                logging.error(
                    "Settings: periodic save to %s failed; will retry.",
                    self._config_path,
                    exc_info=True,
                )
                return

            with self._lock:
                if self._generation == gen_at_start:
                    self._dirty = False
                    logging.debug("Settings: periodic save complete.")
                # else: a new mutation arrived during the write; store stays dirty.
