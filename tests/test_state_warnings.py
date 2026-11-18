"""tests/test_state_warnings.py

The maintenance warnings are a pure function of one state snapshot.
"""
from __future__ import annotations

import ast
import sys
from dataclasses import replace
from pathlib import Path

_CORE = str(Path(__file__).resolve().parent.parent / "core")
if _CORE not in sys.path:
    sys.path.insert(0, _CORE)

import autostream_dial_warnings as dw
from autostream_playback_stats import make_fallback_input_snapshot
from autostream_state import empty_playback_snapshot, store
from fake_store import FakeStore


def _playback(**input_overrides):
    base = make_fallback_input_snapshot(
        1, "Input 1", is_turntable=True,
        stylus_life_hours=500, belt_life_hours=500, bearing_life_hours=500)
    inp = replace(base, **input_overrides)
    return replace(empty_playback_snapshot(), inputs={1: inp})


def test_the_result_depends_only_on_the_snapshot_it_is_given(fake_store):
    fake_store.playback(_playback(belt_overdue=True))
    held = store().snapshot()
    fake_store.playback(empty_playback_snapshot())
    assert dw._derive_warnings(held)[0].id == "belt_in1"
    assert dw._derive_warnings(store().snapshot()) == []
    assert dw._derive_warnings(held) == dw._derive_warnings(held)


def test_a_playback_publish_changes_the_result(fake_store):
    assert dw._derive_warnings(store().snapshot()) == []
    fake_store.playback(_playback(stylus_overdue=True))
    (w,) = dw._derive_warnings(store().snapshot())
    assert (w.id, w.severity) == ("stylus_in1", "critical")


def test_current_warnings_reads_the_stored_snapshot(fake_store, monkeypatch):
    monkeypatch.setattr(dw, "_psu_warnings", lambda: [])
    monkeypatch.setattr(dw, "WARNING_PROVIDERS", (dw._maintenance_provider,))
    fake_store.playback(_playback(bearing_warning=True))
    assert [w.id for w in dw.current_warnings()] == ["bearing_in1"]


def test_the_module_does_not_import_core():
    tree = ast.parse((Path(_CORE) / "autostream_dial_warnings.py").read_text(encoding="utf-8"))
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            names.add(node.module or "")
    assert "autostream_core" not in names
