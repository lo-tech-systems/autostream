#!/usr/bin/env python3
"""autostream_runtime_state.py

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.

RuntimeStateStore.

Brings the runtime-state file (STATE_PATH: PIN override, commissioning
marker, known outputs) under the same schema/dirty-flag/debounce discipline
``SettingsStore`` already has for the main config file. Before this module
existed, every runtime-state field was read/written via bare
``load_state``/``save_state`` calls (``autostream_config.py``) with no
in-memory canonical store and no debounce -- every write was a synchronous
read-modify-write-atomic-replace, one file open per call.

Deliberately narrower than ``SettingsStore``: every field routed to this
store must be ``LiveClass.PASSIVE`` -- ``register_field()``
(``autostream_settings_schema.py``) already asserts this at *registration*
time for any row with ``store="runtime_state"``, so a misclassified row
fails fast at import, not silently in production.

CRITICAL exception: PIN-override writes keep today's synchronous
durability guarantee -- moving a security-adjacent field
onto a debounced store, unqualified, would silently change it from "always
durable immediately" to "durable within 5s by default." ``set()`` alone
never does this; a PIN-override write must be followed by an explicit
``flush(sync=True)`` call, exactly mirroring ``SettingsStore``'s own
sync-flush callers (first-boot completion, reboot, ...). This module does
not itself enforce that callers remember to do so -- see
``autostream_webui_api.py``'s and any future PIN-write call site's own
docstring for the explicit flush call once one migrates onto this store.

SCOPE -- FOUNDATION ONLY, NOT YET WIRED. This module deliberately stops at
"built and tested". NOTHING in the running appliance uses this store yet: every
existing runtime-state call site (``autostream_auth.py``'s
``read_pin_override``/``write_pin_override``, ``autostream_commissioning.py``'s
marker read/write, ``autostream_webui_api.py``'s known-outputs merge) still
goes through bare ``load_state``/``save_state`` and is untouched by this
item. Those are security- and commissioning-critical paths, heavily tested
elsewhere, and moving them is a separate, deliberately-deferred item. The
four fields below are registered in the schema table so that item has
ready-made rows to migrate onto -- registering a row wires nothing on its
own. Deferred follow-up work, not forgotten.
"""
from __future__ import annotations

import copy
import logging
import threading
from typing import Callable, Optional

from autostream_config import load_state, save_state
from autostream_settings_schema import LiveClass, get_field_spec, register_field

# Default interval for the background dirty-save cycle -- same 5-second
# cadence as SettingsStore's, for the same reason: rapid successive edits
# coalesce into one disk write while bounding what an abrupt power loss
# could lose.
RUNTIME_STATE_SAVE_INTERVAL_SECONDS = 5.0


class RuntimeStateStore:
    """Canonical in-memory runtime-state dict.

    Structurally a narrower sibling of ``SettingsStore``: same two-tier
    lock / dirty-flag / debounce shape (see that class's own docstring for
    the lock-order rationale, which applies identically here), but with no
    live/reload dispatch -- every field this store holds is PASSIVE by
    construction.
    """

    def __init__(
        self,
        state_path: str,
        *,
        _save_interval_seconds: float = RUNTIME_STATE_SAVE_INTERVAL_SECONDS,
        _writer: Optional[Callable[[str, dict], None]] = None,
        _stop_event: Optional[threading.Event] = None,
    ) -> None:
        self._state_path = state_path
        self._save_interval = float(_save_interval_seconds)
        self._writer: Callable[[str, dict], None] = _writer or save_state
        self._stop_event = _stop_event or threading.Event()

        self._lock = threading.Lock()
        self._raw: dict = {}
        self._dirty: bool = False
        self._generation: int = 0
        self._write_lock = threading.Lock()

        try:
            self._raw = load_state(state_path)
        except Exception:
            logging.warning(
                "RuntimeState: could not load %s at startup; using empty state.",
                state_path, exc_info=True,
            )
            self._raw = {}

        self._thread: Optional[threading.Thread] = threading.Thread(
            target=self._save_worker, name="runtime-state-save", daemon=True,
        )
        self._thread.start()

    @property
    def state_path(self) -> str:
        return self._state_path

    # ── Read ─────────────────────────────────────────────────────────────

    def raw_snapshot(self) -> dict:
        with self._lock:
            return copy.deepcopy(self._raw)

    def get(self, path: str) -> object:
        """Return the current in-memory value at *path*, or ``None`` if unset."""
        spec = self._resolve_spec(path)
        with self._lock:
            return copy.deepcopy(self._raw.get(spec.section, {}).get(spec.key))

    # ── Write ────────────────────────────────────────────────────────────

    def update(self, mutator: Callable[[dict], None]) -> None:
        """Apply *mutator* to a copy of the raw state dict and commit.

        Same contract as ``SettingsStore.update()`` -- see that method's
        docstring.
        """
        with self._lock:
            raw_copy = copy.deepcopy(self._raw)
            mutator(raw_copy)
            self._raw = raw_copy
            self._generation += 1
            self._dirty = True

    def set(self, path: str, value: object) -> object:
        """Validate/coerce *value* per the field's schema row and commit it.

        Debounced by default (marks dirty, next flush cycle within
        ``RUNTIME_STATE_SAVE_INTERVAL_SECONDS``) -- callers needing the
        CRITICAL synchronous-durability exception (PIN override) must call
        ``flush(sync=True)`` themselves immediately after. Returns the
        normalised value.
        """
        spec = self._resolve_spec(path)
        normalized = spec.validate(value) if spec.validate is not None else value
        section, key = spec.section, spec.key

        def _mutator(raw: dict) -> None:
            raw.setdefault(section, {})[key] = normalized

        self.update(_mutator)
        return normalized

    def _resolve_spec(self, path: str):
        spec = get_field_spec(path)
        if spec is None or spec.section is None or spec.key is None:
            raise KeyError(f"Unknown runtime_state field: {path}")
        if spec.store != "runtime_state":
            raise ValueError(f"{path!r} is not a runtime_state-backed field")
        return spec

    def flush(self, *, sync: bool = False, timeout: float = 2.0) -> bool:
        """Debounced by default (returns True immediately -- the dirty flag
        set() already left behind is picked up by the background thread on
        its own cadence). ``sync=True`` blocks for a durability barrier,
        matching ``SettingsStore.save_now()``'s contract exactly -- this is
        the CRITICAL synchronous exception PIN-override writes must use.
        """
        if not sync:
            return True
        return self.save_now(timeout=timeout)

    def save_now(self, timeout: float = 10.0) -> bool:
        """Synchronous durability barrier -- same shape as
        ``SettingsStore.save_now()`` (see that method's docstring for the
        write-lock/generation-recheck rationale, which applies identically
        here: whichever save acquires the write lock last is guaranteed to
        write last).
        """
        with self._lock:
            raw_copy = copy.deepcopy(self._raw)
            gen_at_start = self._generation

        _result: list[bool] = []
        _cancel = threading.Event()

        def _write() -> None:
            with self._write_lock:
                with self._lock:
                    if self._generation != gen_at_start:
                        return
                if _cancel.is_set():
                    return
                try:
                    self._writer(self._state_path, raw_copy)
                    _result.append(True)
                except Exception:
                    logging.error("RuntimeState: save_now failed", exc_info=True)
                    _result.append(False)

        t = threading.Thread(target=_write, daemon=True)
        t.start()
        t.join(timeout)

        if t.is_alive():
            _cancel.set()
            logging.error("RuntimeState: save_now timed out after %.1fs", timeout)
            return False

        if not _result or not _result[0]:
            return False

        with self._lock:
            if self._generation == gen_at_start:
                self._dirty = False
        return True

    # ── Lifecycle ────────────────────────────────────────────────────────

    def close(self, *, save: bool = True) -> None:
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=15.0)
            self._thread = None
        if save:
            with self._lock:
                is_dirty = self._dirty
            if is_dirty:
                self.save_now()

    # ── Background thread ────────────────────────────────────────────────

    def _save_worker(self) -> None:
        while not self._stop_event.wait(self._save_interval):
            self._run_save_cycle()

    def _run_save_cycle(self) -> None:
        with self._lock:
            if not self._dirty:
                return
            raw_copy = copy.deepcopy(self._raw)
            gen_at_start = self._generation

        with self._write_lock:
            with self._lock:
                if not self._dirty or self._generation != gen_at_start:
                    return
            try:
                self._writer(self._state_path, raw_copy)
            except Exception:
                logging.error(
                    "RuntimeState: periodic save to %s failed; will retry.",
                    self._state_path, exc_info=True,
                )
                return
            with self._lock:
                if self._generation == gen_at_start:
                    self._dirty = False


# -----------------------------------------------------------------------------
# Schema rows -- runtime-state fields live in the *same* SETTINGS_SCHEMA
# table as the settings-file fields, distinguished only by
# FieldSpec.store="runtime_state" (not a second, parallel schema).
# -----------------------------------------------------------------------------

def _validate_pin_override(value: object) -> str:
    return str(value or "").strip()


def _validate_bool_flag(value: object) -> bool:
    return bool(value)


def _validate_known_outputs(value: object) -> dict:
    return dict(value or {})


register_field(
    "runtime_state.auth.pin_override", "auth", "pin_override",
    _validate_pin_override, live_class=LiveClass.PASSIVE, store="runtime_state",
)
register_field(
    "runtime_state.first_boot.required", "first_boot", "required",
    _validate_bool_flag, live_class=LiveClass.PASSIVE, store="runtime_state",
)
register_field(
    "runtime_state.first_boot.completed", "first_boot", "completed",
    _validate_bool_flag, live_class=LiveClass.PASSIVE, store="runtime_state",
)
register_field(
    "runtime_state.owntone.known_outputs", "owntone", "known_outputs",
    _validate_known_outputs, live_class=LiveClass.PASSIVE, store="runtime_state",
)
