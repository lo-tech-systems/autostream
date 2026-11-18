"""tests/test_settings_part.py

The settings generation as a state part: the store's commit hooks run after
its lock is released, the process hook only moves the generation forward, and
a hook that raises never fails the commit.
"""
from __future__ import annotations

import json
import sys
import threading
from pathlib import Path

import pytest

_CORE = str(Path(__file__).resolve().parent.parent / "core")
if _CORE not in sys.path:
    sys.path.insert(0, _CORE)

import autostream_core as core
import autostream_state as state
from autostream_settings import SettingsStore


def _store(tmp_path):
    p = tmp_path / "cfg.json"
    p.write_text(json.dumps({}))
    return SettingsStore(str(p), _save_interval_seconds=60.0, _writer=lambda path, data: None)


def _bump(raw):
    raw["x"] = raw.get("x", 0) + 1


def test_a_hook_runs_after_the_stores_lock_is_released(tmp_path):
    s = _store(tmp_path)
    try:
        seen = []
        s.add_commit_hook(lambda gen: seen.append((gen, s._lock.locked())))
        s.update(_bump)
        assert seen == [(1, False)]
    finally:
        s.close(save=False)


def test_reload_from_disk_runs_the_hooks_with_the_new_generation(tmp_path):
    s = _store(tmp_path)
    try:
        seen = []
        s.add_commit_hook(lambda gen: seen.append((gen, s._lock.locked())))
        s.update(_bump)
        s.save_now()
        s.reload_from_disk()
        assert seen == [(1, False), (2, False)]
    finally:
        s.close(save=False)


def test_a_raising_hook_does_not_fail_the_commit_or_stop_later_hooks(tmp_path):
    s = _store(tmp_path)
    try:
        later = []

        def boom(gen):
            raise RuntimeError("hook failed")

        s.add_commit_hook(boom)
        s.add_commit_hook(later.append)
        snap = s.update(_bump)
        assert snap is not None
        assert later == [1]
    finally:
        s.close(save=False)


def test_the_process_hook_moves_the_generation_forward_only(fake_store):
    core._publish_settings_generation(5)
    assert fake_store.snapshot.settings.generation == 5
    core._publish_settings_generation(3)
    assert fake_store.snapshot.settings.generation == 5
    core._publish_settings_generation(6)
    assert fake_store.snapshot.settings.generation == 6


def test_the_generation_is_monotonic_under_two_threads(fake_store, tmp_path):
    s = _store(tmp_path)
    try:
        s.add_commit_hook(core._publish_settings_generation)
        seen = []
        state.store().subscribe(lambda change: seen.append(state.store().snapshot().settings.generation))

        def work():
            for _ in range(50):
                s.update(_bump)

        threads = [threading.Thread(target=work) for _ in range(2)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert state.store().snapshot().settings.generation == 100
    finally:
        s.close(save=False)


def test_bootstrap_installs_the_hook_on_the_settings_store():
    import inspect

    src = inspect.getsource(core._bootstrap)
    assert "settings.add_commit_hook(_publish_settings_generation)" in src
