"""tests/test_default_set_writers.py

The writers of the Auto-Start set: the owntone.default_outputs field, the
compat writers kept for the Setup select and the volume slider, first boot,
and the outputs.save_default intent. Whatever the order of two writes, the
store and the output authority end holding the same set.
"""
from __future__ import annotations

import json
import sys
import threading
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

_CORE = str(Path(__file__).resolve().parent.parent / "core")
if _CORE not in sys.path:
    sys.path.insert(0, _CORE)

import lockcheck
import autostream_live_config as live
import autostream_state as state
from autostream_intents.table import Intent, submit
from autostream_settings import SettingsStore, as_view
from autostream_settings_schema import get_field_spec
from autostream_state import Origin
from autostream_state.outputs import get_authority
from output_fakes import FakeBackend, row, snap

T0 = 1000.0


@pytest.fixture
def w(monkeypatch):
    a = get_authority()
    fb = FakeBackend(a)
    monkeypatch.setattr(a, "_clock", lambda: T0)
    a.start(fb)
    return SimpleNamespace(a=a, fb=fb)


@pytest.fixture
def store(tmp_path):
    path = tmp_path / "config.json"
    path.write_text(json.dumps({"owntone": {
        "base_url": "http://localhost:3689",
        "output_name": "Lounge",
        "volume_percent": 20,
    }}))
    s = SettingsStore(str(path), _save_interval_seconds=9999, _writer=MagicMock())
    live.bind_settings_store(s)
    yield s
    live.bind_settings_store(None)


def merge(w, rows):
    w.a.merge_for_tests(list(rows), boot="b0", now=T0)


def save():
    return submit(Intent("outputs.save_default", {}, Origin.USER, "test"))


def members(store):
    return [(m.id, m.name, m.volume) for m in store.snapshot().owntone.default_outputs]


def authority_members():
    return [(m.id, m.name, m.volume) for m in snap().default_members]


def write(store, path, value):
    return store.set(path, value, state=SimpleNamespace(settings=as_view(store)))


class TestDefaultOutputsField:
    def test_it_writes_the_set_and_drops_the_legacy_name(self, store, w):
        write(store, "owntone.default_outputs", [
            {"id": "A", "name": "Lounge", "volume": 30},
            {"id": "", "name": "Kitchen", "volume": 40},
        ])
        raw = store._raw["owntone"]
        assert "output_name" not in raw
        assert members(store) == [("A", "Lounge", 30), ("", "Kitchen", 40)]
        assert authority_members() == members(store)

    def test_an_empty_list_is_refused(self, store):
        with pytest.raises(ValueError):
            get_field_spec("owntone.default_outputs").validate([])

    @pytest.mark.parametrize("bad", [
        "Lounge",
        [{"name": "", "volume": 10}],
        [{"name": "Lounge"}],
        [{"name": "Lounge", "volume": 101}],
        ["Lounge"],
        [{"name": "n" * 257, "volume": 10}],
    ])
    def test_a_malformed_list_is_refused(self, store, bad):
        with pytest.raises(ValueError):
            get_field_spec("owntone.default_outputs").validate(bad)

    def test_a_repeated_member_is_dropped(self, store):
        got = get_field_spec("owntone.default_outputs").validate([
            {"id": "A", "name": "Lounge", "volume": 30},
            {"id": "A", "name": "Lounge", "volume": 50},
        ])
        assert got == [{"id": "A", "name": "Lounge", "volume": 30}]


class TestCompatWriters:
    def test_the_name_writes_one_member_with_the_units_id(self, store, w):
        merge(w, [row("K1", "Kitchen")])
        write(store, "owntone.output_name", "Kitchen")
        assert members(store) == [("K1", "Kitchen", 20)]
        assert "output_name" not in store._raw["owntone"]
        assert authority_members() == [("K1", "Kitchen", 20)]

    def test_the_name_of_an_unknown_speaker_has_no_id(self, store, w):
        write(store, "owntone.output_name", "Garage")
        assert members(store) == [("", "Garage", 20)]

    def test_the_volume_moves_a_single_member_with_it(self, store, w):
        write(store, "owntone.default_outputs", [{"id": "A", "name": "Lounge", "volume": 30}])
        write(store, "owntone.volume_percent", 55)
        assert store.snapshot().owntone.volume_percent == 55
        assert members(store) == [("A", "Lounge", 55)]
        assert authority_members() == [("A", "Lounge", 55)]
        assert get_authority().start_volume() == 55

    def test_the_volume_leaves_a_larger_set_alone(self, store, w):
        write(store, "owntone.default_outputs", [
            {"id": "A", "name": "Lounge", "volume": 30},
            {"id": "B", "name": "Kitchen", "volume": 40},
        ])
        write(store, "owntone.volume_percent", 55)
        assert members(store) == [("A", "Lounge", 30), ("B", "Kitchen", 40)]


class TestFirstBoot:
    def _commit(self, store, args):
        ctx = SimpleNamespace(settings=as_view(store))
        return submit(Intent("first_boot.commit", args, Origin.USER, "webui", context=ctx))

    def test_the_output_step_writes_a_one_member_set(self, store, w):
        merge(w, [row("K1", "Kitchen")])
        assert self._commit(store, {"step": "output", "output_name": "Kitchen"}).ok
        assert "output_name" not in store._raw["owntone"]
        assert members(store) == [("K1", "Kitchen", 20)]

    def test_the_finish_step_keeps_one_speaker_and_one_volume(self, store, w):
        assert self._commit(store, {"step": "output", "output_name": "Kitchen"}).ok
        reply = self._commit(store, {
            "step": "finish", "skip_input1": True, "volume_percent": 35})
        assert reply.ok
        assert store.snapshot().owntone.volume_percent == 35
        assert members(store) == [("", "Kitchen", 35)]


class TestSaveDefault:
    def test_the_playing_speakers_become_the_set_in_part_order(self, store, w):
        merge(w, [
            row("A", "Lounge", selected=True, volume_percent=30),
            row("B", "Kitchen", selected=False),
            row("C", "Hall", selected=True, volume_percent=45),
        ])
        reply = save()
        assert reply.ok and reply.result["members"] == [
            {"id": "A", "name": "Lounge", "volume": 30},
            {"id": "C", "name": "Hall", "volume": 45},
        ]
        assert members(store) == [("A", "Lounge", 30), ("C", "Hall", 45)]
        assert "output_name" not in store._raw["owntone"]
        assert authority_members() == members(store)
        assert snap().default_matches is True

    def test_a_muted_speaker_is_saved_at_the_level_it_returns_to(self, store, w):
        merge(w, [row("A", "Lounge", selected=True, volume_percent=40)])
        w.a.mute_all(Origin.USER)
        assert save().ok
        assert members(store) == [("A", "Lounge", 40)]

    def test_a_speaker_at_level_zero_is_saved_at_the_start_volume(self, store, w):
        merge(w, [row("A", "Lounge", selected=True, volume_percent=0)])
        assert save().ok
        assert members(store) == [("A", "Lounge", 20)]
        assert snap().default_matches is True

    def test_a_speaker_waiting_for_a_pin_is_not_saved(self, store, w):
        merge(w, [
            row("A", "Lounge", selected=True, volume_percent=30),
            row("P", "Pinned", selected=True, needs_auth_key=True),
        ])
        assert save().ok
        assert members(store) == [("A", "Lounge", 30)]

    def test_nothing_selected_is_refused_and_changes_nothing(self, store, w):
        merge(w, [row("A", "Lounge")])
        reply = save()
        assert not reply.ok and reply.error == "nothing_selected"
        assert members(store) == [("", "Lounge", 20)]

    def test_an_unbound_store_is_refused(self, w):
        live.bind_settings_store(None)
        merge(w, [row("A", "Lounge", selected=True, volume_percent=30)])
        reply = save()
        assert not reply.ok and reply.error == "settings_unavailable"


class TestEitherOrder:
    @pytest.fixture
    def tracked(self):
        s = state.store()
        s.reset_for_tests(track_locks=True)
        lockcheck.install(s)
        yield s
        lockcheck.uninstall()
        s._lock = threading.Lock()
        s._cond = threading.Condition(s._lock)

    FIELD = [{"id": "K", "name": "Kitchen", "volume": 35}]

    def _end_equal(self, store, tracked):
        assert authority_members() == members(store)
        assert tracked.lock_violations == []
        assert lockcheck.ACQUIRED_UNDER_STORE == []

    def test_a_field_write_then_a_save(self, tracked, store, w):
        merge(w, [row("A", "Lounge", selected=True, volume_percent=30)])
        write(store, "owntone.default_outputs", self.FIELD)
        assert save().ok
        assert members(store) == [("A", "Lounge", 30)]
        self._end_equal(store, tracked)

    def test_a_save_then_a_field_write(self, tracked, store, w):
        merge(w, [row("A", "Lounge", selected=True, volume_percent=30)])
        assert save().ok
        write(store, "owntone.default_outputs", self.FIELD)
        assert members(store) == [("K", "Kitchen", 35)]
        self._end_equal(store, tracked)

    def test_concurrent_writes_end_equal(self, tracked, store, w):
        merge(w, [row("A", "Lounge", selected=True, volume_percent=30)])
        for _ in range(20):
            threads = [
                threading.Thread(target=save),
                threading.Thread(target=write, args=(store, "owntone.default_outputs", self.FIELD)),
            ]
            for t in threads:
                t.start()
            for t in threads:
                t.join()
            assert authority_members() == members(store)
        self._end_equal(store, tracked)


class TestSetupSummary:
    @staticmethod
    def _ctx(names, volume=20):
        from autostream_config import DefaultOutput
        owntone = SimpleNamespace(
            default_outputs=tuple(DefaultOutput("", n, volume) for n in names), volume_percent=volume)
        return SimpleNamespace(parsed=SimpleNamespace(owntone=owntone))

    def test_one_member_reads_as_it_did(self):
        from webui.browser.setup import cards_playback
        assert cards_playback.summary_playback(self._ctx(["Lounge"], 30)) == "Lounge · 30%"

    def test_members_are_listed_in_order(self):
        from webui.browser.setup import cards_playback
        assert cards_playback.summary_playback(self._ctx(["Lounge", "Kitchen"])) == "Lounge, Kitchen · 20%"

    def test_no_member_says_so(self):
        from webui.browser.setup import cards_playback
        assert cards_playback.summary_playback(self._ctx([])).startswith("No speaker selected")
