"""tests/test_state_view_cases_shape.py

The derivation case table (tests/fixtures/state_view_cases.json) is written by
hand, so its parts could drift from what the appliance really sends. Every
part dict in every case is checked here against the dataclass that makes the
wire shape: its keys must be fields of that dataclass (an output unit also
carries ``offline``, which the state body adds), and so must the keys of the
records inside it that have a dataclass of their own.
"""
from __future__ import annotations

import dataclasses
import json
import sys
from pathlib import Path

import pytest

_CORE = str(Path(__file__).resolve().parent.parent / "core")
if _CORE not in sys.path:
    sys.path.insert(0, _CORE)

import autostream_state as state
from autostream_playback_stats import InputPlaybackSnapshot, PlaybackSnapshot
from autostream_players import OutputInfo
from track_id.models import TrackIdentificationSnapshot

CASES = json.loads((Path(__file__).parent / "fixtures" / "state_view_cases.json").read_text(encoding="utf-8"))

PART_TYPES = {
    "session": state.SessionPart, "repeat": state.RepeatPart, "track": state.TrackPart,
    "inputs": state.InputsPart, "monitor": state.MonitorRuntimeInfo, "playback": PlaybackSnapshot,
    "health": state.HealthPart, "settings": state.SettingsPart, "outputs": state.OutputsPart,
    "eq": state.EqPart, "devices": state.DevicesPart, "appliance": state.AppliancePart,
    "dials": state.DialsPart, "warnings": state.WarningsPart,
}


def _fields(cls) -> set:
    return {f.name for f in dataclasses.fields(cls)}


# (part, key) -> how to read the records in that key: "list" of records, or a
# "dict" of them by name, and the dataclass each is.
RECORDS = {
    ("inputs", "entries"): ("list", state.InputEntry),
    ("outputs", "units"): ("list", state.OutputUnitView),
    ("outputs", "default_members"): ("list", state.DefaultMemberView),
    ("outputs", "start_failure"): ("one", state.StartFailure),
    ("track", "entries"): ("dict", TrackIdentificationSnapshot),
    ("playback", "inputs"): ("dict", InputPlaybackSnapshot),
    ("warnings", "entries"): ("list", state.WarningEntry),
}
EXTRA = {state.OutputUnitView: {"offline"}}


def _check_record(cls, rec, where: str) -> None:
    allowed = _fields(cls) | EXTRA.get(cls, set())
    assert set(rec) <= allowed, f"{where}: unknown keys {sorted(set(rec) - allowed)} for {cls.__name__}"
    if cls is state.OutputUnitView and isinstance(rec.get("reported"), dict):
        extra = set(rec["reported"]) - _fields(OutputInfo)
        assert not extra, f"{where}: unknown keys {sorted(extra)} for OutputInfo"


def _parts_of(case) -> dict:
    return case.get("parts") or (case.get("view") or {}).get("parts") or {}


def test_the_table_is_large_enough_and_every_function_has_four_cases():
    assert CASES["version"] == 1 and len(CASES["cases"]) >= 40
    by_fn: dict[str, int] = {}
    for c in CASES["cases"]:
        by_fn[c["fn"]] = by_fn.get(c["fn"], 0) + 1
    assert all(n >= 4 for n in by_fn.values()), by_fn
    assert set(by_fn) == {"playing", "live", "activeInput", "nowPlaying", "speakerRows",
                          "masterVolume", "startFailure", "repeatControls", "warningsFor"}


@pytest.mark.parametrize("case", CASES["cases"], ids=lambda c: c["name"])
def test_a_case_uses_only_fields_the_appliance_sends(case):
    for name, part in _parts_of(case).items():
        assert name in PART_TYPES, f"unknown part {name}"
        if not isinstance(part, dict):
            continue
        assert set(part) <= _fields(PART_TYPES[name]), (
            f"{name}: unknown keys {sorted(set(part) - _fields(PART_TYPES[name]))}")
        for key, value in part.items():
            spec = RECORDS.get((name, key))
            if spec is None or value is None:
                continue
            kind, cls = spec
            records = [value] if kind == "one" else value.values() if kind == "dict" else value
            for i, rec in enumerate(records):
                _check_record(cls, rec, f"{name}.{key}[{i}]")


def test_every_case_names_its_inputs_and_expectation():
    for c in CASES["cases"]:
        assert {"name", "fn", "expect"} <= set(c), c.get("name")
        assert ("parts" in c) != ("view" in c), c["name"]
    assert len({c["name"] for c in CASES["cases"]}) == len(CASES["cases"])
