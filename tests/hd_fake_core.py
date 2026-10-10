"""A stand-in for DialCore that the HD server, hub and page tests drive: it
holds a snapshot, publishes new ones the way the core does (a sequence, a
condition to wait on, subscriber callbacks), records every action call and
answers each with a configured ActionResult."""
from __future__ import annotations

import dataclasses
import sys
import threading
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
for _p in (str(REPO_ROOT / "dial"), str(REPO_ROOT / "core")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from dial_core_state import ActionResult
from dial_warning_text import WARNING_DESCRIPTORS
from dial_warnings import WarningManager, WarningStore

# The core methods the HD actions call, each recorded and answered.
ACTION_METHODS = (
    "set_focus", "set_output", "step_output_volume", "set_eq", "step_eq", "reset_eq",
    "start_replay", "restart_replay", "stop_replay", "set_repeat_armed", "dismiss_warning",
    "volume_step", "volume_set", "mute_toggle",
)


class FakeCore:
    def __init__(self, snapshot, *, warnings=None, results=None, reboot_result=True, shutdown_result=True):
        self._snapshot = snapshot
        self._cond = threading.Condition()
        self._subscribers: dict = {}
        self._next_handle = 1
        self.warnings = warnings if warnings is not None else WarningManager(
            WARNING_DESCRIPTORS, WarningStore(None),
        )
        self.calls: list = []                 # (method, args, kwargs), in order
        self.results: dict = dict(results or {})   # method -> ActionResult
        self.default_result = ActionResult(True)
        self.reboot_result = reboot_result
        self.shutdown_result = shutdown_result
        self.watches: list = []               # (kind, appliance_id, watcher, on)
        for method in ACTION_METHODS:
            setattr(self, method, self._action(method))

    # ---- what the core's readers use -------------------------------------

    def snapshot(self):
        return self._snapshot

    def wait_for_change(self, seen_seq, timeout):
        with self._cond:
            if not self._cond.wait_for(lambda: self._snapshot.seq > seen_seq, timeout):
                return None
            return self._snapshot

    def subscribe(self, callback) -> int:
        with self._cond:
            handle = self._next_handle
            self._next_handle += 1
            self._subscribers[handle] = callback
        return handle

    def unsubscribe(self, handle) -> None:
        with self._cond:
            self._subscribers.pop(handle, None)

    # ---- driving it ------------------------------------------------------

    def publish(self, snapshot=None, **changes):
        """Publish *snapshot* (or the held one with *changes*) under the
        next sequence and call the subscribers."""
        with self._cond:
            held = snapshot if snapshot is not None else self._snapshot
            self._snapshot = dataclasses.replace(held, seq=self._snapshot.seq + 1, **changes)
            callbacks = list(self._subscribers.values())
            self._cond.notify_all()
        for callback in callbacks:
            callback()
        return self._snapshot

    def set_result(self, method, result: ActionResult) -> None:
        self.results[method] = result

    def calls_to(self, method) -> list:
        """The (args, kwargs) of each call to *method*."""
        return [(a, k) for m, a, k in self.calls if m == method]

    # ---- the core's request methods --------------------------------------

    def _action(self, method):
        def call(*args, **kwargs):
            self.calls.append((method, args, kwargs))
            return self.results.get(method, self.default_result)
        call.__name__ = method
        return call

    def request_dial_reboot(self) -> bool:
        self.calls.append(("request_dial_reboot", (), {}))
        return self.reboot_result

    def request_dial_shutdown(self) -> bool:
        self.calls.append(("request_dial_shutdown", (), {}))
        return self.shutdown_result

    def watch_outputs(self, appliance_id, watcher, on, *, fetch=True) -> None:
        self.watches.append(("outputs", appliance_id, watcher, on))

    def watch_eq(self, appliance_id, watcher, on, *, fetch=True) -> None:
        self.watches.append(("eq", appliance_id, watcher, on))
