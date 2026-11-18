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
from autostream_playback_stats import PlaybackSnapshot
from autostream_players import OutputInfo
from autostream_state import FrozenDict
from autostream_state.freeze import deep_freeze

_LEVEL_DEFAULTS = {
    "label": "Input {index}",
    "dbfs": -60.0,
    "detected_hz": 0.0,
    "detected_khz": "",
    "negotiated_hz": 0,
    "rate_lock": "locked",
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
        if isinstance(snapshot, PlaybackSnapshot):
            return self._put("playback", snapshot)
        # A stand-in object: installed as given, with no digest to compare.
        st = state.store()
        with st._lock:
            st._snapshot = dataclasses.replace(st._snapshot, playback=snapshot)
            st._digests["playback"] = object()
            return st._snapshot

    def health(self, **fields):
        return self._put("health", state.HealthPart(**fields))

    def devices(self, monitor_devices=(), bluetooth_status=None):
        """The device scan's result: each device dict through FrozenDict, the
        status frozen the way a publish freezes it."""
        return self._put("devices", state.DevicesPart(
            monitor_devices=tuple(FrozenDict(d) for d in monitor_devices),
            bluetooth_status=(None if bluetooth_status is None
                              else deep_freeze(bluetooth_status))))

    def settings(self, generation: int):
        return self._put("settings", state.SettingsPart(generation))

    def outputs(self, rows, *, connected: bool = True, boot: str = "b0", start_failure=None):
        """Adopt *rows* (OutputInfo, or dicts of its fields) as a successful
        read, through the output authority's own merge, so the authority and
        the part agree. *start_failure*, a dict of unit_id, reason and
        optionally requester and at, then publishes a failed start of that
        unit."""
        from autostream_state.outputs import get_authority
        infos = [r if isinstance(r, OutputInfo) else OutputInfo(**r) for r in rows]
        get_authority().merge_for_tests(infos, connected=connected, boot=boot)
        if start_failure is not None:
            get_authority().record_start_failure_for_tests(**start_failure)
        return self.snapshot

    def outputs_unreachable(self):
        """The player does not answer: three failed reads."""
        from autostream_state.outputs import get_authority
        get_authority().mark_unreachable_for_tests()
        return self.snapshot

    @staticmethod
    def output_row(id: str, name: str, **fields) -> OutputInfo:
        return OutputInfo(id=id, name=name, **fields)


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


def fake_outputs(rows, connected: bool = True):
    """Put the given output rows into the output authority and return a
    context manager that does nothing, so it can stand in a ``with`` statement
    where a test used to patch the output list."""
    fake = FakeStore()
    if connected:
        fake.outputs(list(rows))
    else:
        fake.outputs_unreachable()
    return contextlib.nullcontext()


def fake_outputs_result(result):
    """As fake_outputs, from a ListOutputsResult-like value: its rows when it
    is ok, otherwise a player that does not answer."""
    return fake_outputs(list(result.outputs), connected=bool(result.ok))


def fake_levels(levels, banner: str = ""):
    """Put the given Web UI level items into the inputs part (one entry per
    item) and return a context manager that does nothing, so it can stand in
    a ``with`` statement where a test used to patch a levels getter."""
    fake = FakeStore()
    entries = []
    for position, lv in enumerate(levels, start=1):
        entry = fake.input_entry(
            lv.get("index", position), rate_mismatch_hz=int(lv.get("rate_mismatch_hz", 0) or 0))
        # The level is exactly what the test gave, with no defaults filled in.
        entries.append(dataclasses.replace(entry, level=dict(lv)))
    fake.inputs(entries, banner=banner)
    return contextlib.nullcontext()


def fake_playback(snapshot):
    """Put a playback snapshot into the store and return a context manager
    that does nothing, so it can stand in a ``with`` statement where a test
    used to patch a playback getter. A stand-in object (a mock with only the
    attributes a page reads) is installed as given."""
    FakeStore().playback(snapshot)
    return contextlib.nullcontext()


def fake_playback_mock():
    """Install a MagicMock as the playback snapshot. As a context manager it
    yields an object whose ``return_value`` is that mock, so a test that
    configured ``patch(...) as gp`` through ``gp.return_value`` keeps its
    body."""
    from unittest.mock import MagicMock
    from types import SimpleNamespace
    mock = MagicMock()
    FakeStore().playback(mock)
    return contextlib.nullcontext(SimpleNamespace(return_value=mock))


def fake_track(snapshot):
    """Make *snapshot* the active track: a disabled snapshot is a store with
    no identification service; any other is the track entry of an input that
    is capturing. Returns a context manager that does nothing, so it can
    stand in a ``with`` statement where a test used to patch the active-track
    getter."""
    fake = FakeStore()
    if snapshot.state == "disabled":
        fake.track({}, service_enabled=False)
        return contextlib.nullcontext()
    index = int(snapshot.input_index or 1)
    fake.track({index: snapshot}, service_enabled=True)
    inputs = state.store().snapshot().inputs
    entries = [dataclasses.replace(e, capturing=True) if e.index == index else e
               for e in inputs.entries]
    if all(e.index != index for e in entries):
        entries.append(fake.input_entry(index, capturing=True))
    fake.inputs(entries, mismatch=inputs.sample_rate_mismatch_input,
                banner=inputs.sample_rate_warning_text)
    return contextlib.nullcontext()
