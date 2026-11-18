"""tests/test_output_settings_cache.py

The include-Apple-TV choices and the Pause settings as the output authority
and the policy read them: parsed again only when the settings store has
committed since, and the defaults when no store is bound.
"""
from __future__ import annotations

import json
import sys
import threading
from pathlib import Path
from types import MappingProxyType

import pytest

_CORE = str(Path(__file__).resolve().parent.parent / "core")
if _CORE not in sys.path:
    sys.path.insert(0, _CORE)

import autostream_config as cfg
import autostream_live_config as lc
from autostream_settings import SettingsStore


@pytest.fixture
def store(tmp_path):
    path = tmp_path / "config.json"
    path.write_text(json.dumps({}), encoding="utf-8")
    s = SettingsStore(str(path), _save_interval_seconds=9999, _writer=lambda p, d: None)
    snapshots = []
    real = s.snapshot

    def counting():
        snapshots.append(1)
        return real()

    s.snapshot = counting
    s.snapshots = snapshots
    yield s
    s.close(save=False)


def test_unbound_it_gives_the_defaults():
    got = lc.output_settings()
    assert dict(got.include_tv) == {} and got.policy == cfg.OutputsConfig()
    assert lc.include_tv_for("any") is True
    assert lc.output_policy_settings().device_pause_scope == cfg.DEVICE_PAUSE_SCOPE_DEFAULT


def test_an_output_never_chosen_is_played_with_its_apple_tv(store):
    lc.bind_settings_store(store)
    assert lc.include_tv_for("1001") is True


def test_one_snapshot_serves_every_read_of_a_generation(store):
    lc.bind_settings_store(store)
    for _ in range(20):
        lc.include_tv_for("1")
        lc.output_policy_settings()
    assert len(store.snapshots) == 1


def test_a_commit_is_seen_by_the_next_read_and_costs_one_more_snapshot(store):
    lc.bind_settings_store(store)
    assert lc.include_tv_for("1") is True
    store.update(lambda r: r.setdefault("owntone", {}).setdefault("include_tv", {}).update({"1": False}))
    before = len(store.snapshots)           # update() itself takes one
    assert lc.include_tv_for("1") is False and lc.include_tv_for("2") is True
    assert len(store.snapshots) == before + 1
    store.update(lambda r: r.setdefault("outputs", {}).update({"device_pause_scope": "all"}))
    before = len(store.snapshots)
    assert lc.output_policy_settings().device_pause_scope == "all"
    assert lc.output_policy_settings().device_pause_scope == "all"
    assert len(store.snapshots) == before + 1


def test_the_include_tv_choices_cannot_be_changed_through_the_view(store):
    lc.bind_settings_store(store)
    assert isinstance(lc.output_settings().include_tv, MappingProxyType)
    with pytest.raises(TypeError):
        lc.output_settings().include_tv["1"] = False


def test_binding_again_forgets_what_was_cached(store, tmp_path):
    lc.bind_settings_store(store)
    store.update(lambda r: r.setdefault("owntone", {}).setdefault("include_tv", {}).update({"1": False}))
    assert lc.include_tv_for("1") is False
    lc.bind_settings_store(None)
    assert lc.include_tv_for("1") is True


def test_the_reset_is_cheap_when_nothing_touched_the_cache():
    lc.reset_output_settings_for_tests()
    before = threading.active_count()
    for _ in range(10000):
        lc.reset_output_settings_for_tests()
    assert threading.active_count() == before


def test_the_reset_unbinds_after_a_use(store):
    lc.bind_settings_store(store)
    lc.include_tv_for("1")
    lc.reset_output_settings_for_tests()
    assert lc.output_settings().generation == -1
