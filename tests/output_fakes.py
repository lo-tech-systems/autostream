"""tests/output_fakes.py

Doubles shared by the output authority tests: a backend that records every
call and checks that none is made under the authority lock, and an event
source that does nothing.
"""
from __future__ import annotations

import threading

import autostream_state as state
from autostream_players import (
    ActionResult,
    EventChannelInfo,
    ListOutputsResult,
    OutputInfo,
)


def row(id, name=None, **fields):
    return OutputInfo(id=str(id), name=name or f"Speaker {id}", **fields)


def group_row(id, session_state="stopped", **fields):
    """A row from a player whose rows carry a session object."""
    return row(id, session_state=session_state, **fields)


def homepods_row(id, session_state="stopped", **fields):
    """A row from a player whose rows carry has_homepods: an Apple TV whose
    HomePods are present."""
    return group_row(id, session_state, has_homepods=True, **fields)


def snap():
    return state.store().snapshot().outputs


class FakeBackend:
    """Records every call, and asserts that none is made under the authority lock."""

    base_url = "http://player.test:3689"

    def __init__(self, authority):
        self.authority = authority
        self.rows = []
        self.reads = 0
        self.calls = []
        self.list_result = None
        self.results = []             # ActionResults to return, first to last
        self.default = ActionResult(ok=True)
        self.gate = None              # an Event the update_output call waits on
        self.entered = threading.Event()
        self.on_update = None         # called inside update_output
        self.on_list = None
        self.channel = EventChannelInfo(kind="poll", reachable=True)
        self.channel_calls = 0
        self._lock = threading.Lock()

    def _record(self, name, *args, **kwargs):
        assert not self.authority._lock_held_by_current_thread(), f"{name} called under the authority lock"
        with self._lock:
            self.calls.append((name, args, kwargs))

    def _next(self):
        with self._lock:
            return self.results.pop(0) if self.results else self.default

    def list_outputs(self, timeout):
        assert not self.authority._lock_held_by_current_thread(), "list_outputs under the authority lock"
        self.reads += 1
        if self.on_list is not None:
            hook, self.on_list = self.on_list, None
            hook()
        if self.list_result is not None:
            return self.list_result
        return ListOutputsResult(ok=True, outputs=tuple(self.rows))

    def update_output(self, output_id, **fields):
        self._record("update_output", output_id, **fields)
        if self.on_update is not None:
            self.on_update(output_id, fields)
        if self.gate is not None:
            self.entered.set()
            assert self.gate.wait(10), "test gate never opened"
        return self._next()

    def set_selected_outputs(self, ids, timeout):
        self._record("set_selected_outputs", list(ids), timeout=timeout)
        return self._next()

    def stop_and_disable_all(self, timeout):
        self._record("stop_and_disable_all", timeout=timeout)
        return self._next()

    def submit_output_pin(self, output_id, pin, timeout):
        self._record("submit_output_pin", output_id, pin, timeout=timeout)
        return self._next()

    def set_output_hold(self, output_id, held, timeout):
        self._record("set_output_hold", output_id, held, timeout=timeout)
        return self._next()

    def set_output_muted(self, output_id, muted, timeout):
        self._record("set_output_muted", output_id, muted, timeout=timeout)
        return self._next()

    def refresh_runtime_state(self, timeout):
        self._record("refresh_runtime_state", timeout=timeout)
        return self._next()

    def capabilities(self):
        raise AssertionError("capabilities must not be needed")

    def event_channel_info(self):
        assert not self.authority._lock_held_by_current_thread()
        self.channel_calls += 1
        return self.channel

    def updates(self):
        return [(c[1][0], c[2]) for c in self.calls if c[0] == "update_output"]


class FakeSource:
    def __init__(self, kind="poll", connected=False, path=None):
        self.kind = kind
        self._connected = connected
        self._path = path
        self.started = 0
        self.stopped = 0
        self.sink = None

    @property
    def connected(self):
        return self._connected

    def start(self, sink):
        self.started += 1
        self.sink = sink

    def stop(self, timeout=2.0):
        self.stopped += 1


def error(code, text="failed"):
    return ActionResult(ok=False, error=text, error_code=code)
