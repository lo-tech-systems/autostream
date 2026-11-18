"""tests/fake_store.py

Put values into the real state store without going through the owner of each
part, so a test of a reader arranges exactly the parts it reads.

    def test_x(fake_store):
        fake_store.session(True, "input1")
        fake_store.inputs([fake_store.input_entry(1, capturing=True)])
"""
from __future__ import annotations

import contextlib
import dataclasses
import sys
from pathlib import Path

_CORE = str(Path(__file__).resolve().parent.parent / "core")
if _CORE not in sys.path:
    sys.path.insert(0, _CORE)

import autostream_state as state
from autostream_state import FrozenDict

_LEVEL_DEFAULTS = {
    "label": "Input {index}",
    "dbfs": -60.0,
    "detected_hz": 0.0,
    "detected_khz": "",
    "negotiated_hz": 0,
    "rate_lock": "",
    "relock_count": 0,
    "rate_mismatch_hz": 0,
    "rate_mismatch_khz": "",
    "dynamic_rate_matching": False,
    "monitor_supports_rate_matching": True,
    "is_above_threshold": False,
    "vu_history": {},
}


class FakeStore:
    """Writes parts of the process store for a test."""

    @property
    def snapshot(self) -> "state.Snapshot":
        return state.store().snapshot()

    def _put(self, part: str, value):
        return state.store().publish_for_tests(part, value)

    def session(self, active: bool, source=None):
        return self._put("session", state.SessionPart(bool(active), source))

    def repeat(self, block):
        return self._put("repeat", state.RepeatPart(block if isinstance(block, dict) else None))

    def track(self, entries=None, service_enabled: bool = True):
        return self._put("track", state.TrackPart(
            entries=FrozenDict(entries or {}), service_enabled=service_enabled))

    def inputs(self, entries=(), mismatch: int = 0, banner: str = ""):
        return self._put("inputs", state.InputsPart(
            entries=tuple(entries), sample_rate_mismatch_input=mismatch,
            sample_rate_warning_text=banner))

    def input_entry(self, index: int, **fields) -> "state.InputEntry":
        """An input entry. Fields of the Web UI level item (dbfs, rate_lock,
        vu_history ...) land in the level; the entry's own fields (device,
        capturing, replay_origin, rate_note ...) are the entry's."""
        own = {f.name for f in dataclasses.fields(state.InputEntry)} - {"level", "index"}
        entry_args = {k: fields.pop(k) for k in list(fields) if k in own}
        level = {"index": index, **_LEVEL_DEFAULTS}
        level["label"] = level["label"].format(index=index)
        level["rate_mismatch_hz"] = entry_args.get("rate_mismatch_hz", 0)
        level.update(fields)
        args = dict(
            device="", input_type="line", capturing=False, replay_origin=False,
            rate_note=state.RATE_MATCHING_NOTE_DEFAULT,
            sample_rate_text=state.SAMPLE_RATE_TEXT_NOT_RUNNING, rate_mismatch_hz=0,
        )
        args.update(entry_args)
        return state.InputEntry(index=index, level=FrozenDict(level), **args)

    def monitor(self, **fields):
        return self._put("monitor", state.MonitorRuntimeInfo(**fields))

    def playback(self, snapshot):
        return self._put("playback", snapshot)

    def health(self, **fields):
        return self._put("health", state.HealthPart(**fields))

    def settings(self, generation: int):
        return self._put("settings", state.SettingsPart(generation))


def fake_session(value: dict):
    """Put a {"active", "source"} session into the store and return a context
    manager that does nothing, so it can stand in a ``with`` statement where a
    test used to patch a session getter."""
    FakeStore().session(value["active"], value.get("source"))
    return contextlib.nullcontext()


def fake_repeat(block):
    """Put a repeat block (or None) into the store and return a context
    manager that does nothing, so it can stand in a ``with`` statement where
    a test used to patch a repeat getter."""
    FakeStore().repeat(block)
    return contextlib.nullcontext()
