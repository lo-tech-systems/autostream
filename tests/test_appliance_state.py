"""tests/test_appliance_state.py

The appliance and dials parts and the module that owns them: the first pass on
the calling thread, the worker, a source that fails, the poke, and the
authorise and revoke handlers with the dials generation they bump.
"""
from __future__ import annotations

import sys
import threading
import time
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

_CORE = str(Path(__file__).resolve().parent.parent / "core")
if _CORE not in sys.path:
    sys.path.insert(0, _CORE)

import autostream_appliance_state as appliance_state
import autostream_state as state
from fake_store import FakeStore
from autostream_intents import Intent, Origin, submit
from autostream_state import live

UUID = "0123456789abcdef0123"


@pytest.fixture
def sources(monkeypatch):
    """Every source the appliance part reads, as plain values the test sets."""
    values = {
        "id": "aa11bb22cc33dd44ee55", "host": "Turntable.local", "version": "0.8.0",
        "commissioning": False, "pin": True,
        "throttled": 0, "cpu": ("ok", None), "sd": None, "dials": 0, "unlicensed": False,
    }
    monkeypatch.setattr(appliance_state.identity, "get_appliance_id", lambda: values["id"])
    monkeypatch.setattr(appliance_state, "get_system_hostname", lambda: values["host"])
    monkeypatch.setattr(appliance_state, "is_commissioning_required",
                        lambda config, st: values["commissioning"])
    monkeypatch.setattr(appliance_state, "pin_is_set", lambda st: values["pin"])
    monkeypatch.setattr(appliance_state, "_read_get_throttled_value", lambda: values["throttled"])
    monkeypatch.setattr(appliance_state.autostream_system_stats, "get_cpu_thermal_status", lambda previous: values["cpu"])
    monkeypatch.setattr(appliance_state, "sdcard_health_display", lambda: values["sd"])
    monkeypatch.setattr(appliance_state, "_dials_needing_update", lambda: values["dials"])
    monkeypatch.setattr(appliance_state, "_unlicensed", lambda: values["unlicensed"])
    return values


def make_src(version=lambda: "0.8.0"):
    return appliance_state._Sources("c.ini", "s.json", version)


class TestPass:
    def test_it_publishes_what_the_sources_say(self, sources):
        appliance_state._run_pass(make_src())
        assert state.store().snapshot().appliance == state.AppliancePart(
            id="aa11bb22cc33dd44ee55", hostname="Turntable", version="0.8.0",
            configured=True, pin_set=True)

    def test_a_commissioning_appliance_is_not_configured(self, sources):
        sources["commissioning"] = True
        appliance_state._run_pass(make_src())
        assert state.store().snapshot().appliance.configured is False

    def test_no_identity_is_an_empty_id(self, sources):
        sources["id"] = None
        appliance_state._run_pass(make_src())
        assert state.store().snapshot().appliance.id == ""

    def test_a_source_that_fails_keeps_its_last_value_and_the_others_move(self, sources):
        appliance_state._run_pass(make_src())
        sources["pin"] = False

        def broken(st):
            raise OSError("unreadable")

        with patch.object(appliance_state, "pin_is_set", broken):
            sources["host"] = "Kitchen"
            appliance_state._run_pass(make_src())
        part = state.store().snapshot().appliance
        assert part.pin_set is True and part.hostname == "Kitchen"

    def test_an_unchanged_pass_moves_nothing(self, sources):
        appliance_state._run_pass(make_src())
        before = state.store().snapshot().part_versions.get("appliance")
        appliance_state._run_pass(make_src())
        assert state.store().snapshot().part_versions.get("appliance") == before


class TestStart:
    def test_the_first_pass_runs_on_the_calling_thread(self, sources):
        stop = threading.Event()
        threads = []
        real = threading.Thread

        class Recording(real):
            def start(self):
                threads.append(self)
                # The part is complete before the worker exists.
                assert state.store().snapshot().appliance.id == "aa11bb22cc33dd44ee55"
                super().start()

        with patch.object(appliance_state.threading, "Thread", Recording):
            worker = appliance_state.start(
                stop, config_path="c.ini", state_path="s.json", settings=None,
                app_version=lambda: "0.8.0")
        try:
            assert threads == [worker] and worker.daemon and worker.name == "appliance-state"
        finally:
            stop.set()
            appliance_state.poke()
            worker.join(5.0)
        assert not worker.is_alive()

    def test_a_first_pass_that_raises_does_not_stop_the_start(self, sources, caplog):
        stop = threading.Event()
        stop.set()
        with patch.object(appliance_state, "_run_pass", side_effect=RuntimeError("boom")):
            worker = appliance_state.start(
                stop, config_path="c.ini", state_path="s.json", settings=None,
                app_version=lambda: "v")
        worker.join(5.0)
        assert any("first pass failed" in r.message for r in caplog.records)

    def test_a_poke_makes_the_worker_look_again(self, sources, monkeypatch):
        monkeypatch.setattr(appliance_state, "_PERIOD_S", 60.0)
        stop = threading.Event()
        worker = appliance_state.start(
            stop, config_path="c.ini", state_path="s.json", settings=None,
            app_version=lambda: "0.8.0")
        try:
            sources["host"] = "Lounge"
            live.state_refresh()
            deadline = time.monotonic() + 5.0
            while time.monotonic() < deadline and state.store().snapshot().appliance.hostname != "Lounge":
                time.sleep(0.01)
            assert state.store().snapshot().appliance.hostname == "Lounge"
        finally:
            stop.set()
            appliance_state.poke()
            worker.join(5.0)

    def test_the_worker_looks_again_on_its_timer(self, sources, monkeypatch):
        monkeypatch.setattr(appliance_state, "_PERIOD_S", 0.05)
        stop = threading.Event()
        worker = appliance_state.start(
            stop, config_path="c.ini", state_path="s.json", settings=None,
            app_version=lambda: "0.8.0")
        try:
            sources["pin"] = False
            deadline = time.monotonic() + 5.0
            while time.monotonic() < deadline and state.store().snapshot().appliance.pin_set:
                time.sleep(0.01)
            assert state.store().snapshot().appliance.pin_set is False
        finally:
            stop.set()
            appliance_state.poke()
            worker.join(5.0)

    def test_a_pass_that_raises_is_logged_once_and_the_loop_carries_on(self, sources, monkeypatch, caplog):
        monkeypatch.setattr(appliance_state, "_PERIOD_S", 0.02)
        calls = []

        def failing(src):
            calls.append(1)
            raise RuntimeError("same message")

        stop = threading.Event()
        with patch.object(appliance_state, "_run_pass", failing):
            worker = appliance_state.start(
                stop, config_path="c.ini", state_path="s.json", settings=None,
                app_version=lambda: "v")
            deadline = time.monotonic() + 5.0
            while time.monotonic() < deadline and len(calls) < 5:
                time.sleep(0.01)
            stop.set()
            appliance_state.poke()
            worker.join(5.0)
        assert len(calls) >= 5
        assert sum("appliance state pass failed" in r.message for r in caplog.records) == 1


WARNINGS_PART = lambda: state.store().snapshot().warnings


class TestWarningsPass:
    def test_it_publishes_what_the_sources_say(self, sources):
        sources["throttled"] = 0x1
        sources["cpu"] = ("high", 72.0)
        sources["dials"] = 2
        appliance_state._run_pass(make_src())
        assert [e.id for e in WARNINGS_PART().entries] == ["psu", "cpu_temp", "dial_update"]
        assert all(e.incident == "" for e in WARNINGS_PART().entries)

    def test_an_unchanged_pass_moves_nothing(self, sources):
        sources["throttled"] = 0x1
        appliance_state._run_pass(make_src())
        before = state.store().snapshot().part_versions["warnings"]
        appliance_state._run_pass(make_src())
        assert state.store().snapshot().part_versions["warnings"] == before

    def test_a_failing_source_drops_only_its_own_warning(self, sources, monkeypatch):
        sources["throttled"] = 0x1
        sources["dials"] = 1

        def broken():
            raise OSError("no vcgencmd")

        monkeypatch.setattr(appliance_state, "_read_get_throttled_value", broken)
        appliance_state._run_pass(make_src())
        assert [e.id for e in WARNINGS_PART().entries] == ["dial_update"]

    def test_the_sd_level_is_held_between_passes(self, sources):
        src = make_src()
        sources["sd"] = 8
        appliance_state._run_pass(src)
        assert WARNINGS_PART().entries[0].severity == "critical"
        sources["sd"] = 14
        appliance_state._run_pass(src)
        assert WARNINGS_PART().entries[0].severity == "critical"
        sources["sd"] = 20
        appliance_state._run_pass(src)
        assert WARNINGS_PART().entries[0].severity == "warning"
        sources["sd"] = 30
        appliance_state._run_pass(src)
        assert WARNINGS_PART().entries == ()

    def test_the_thermal_status_is_passed_back_as_previous(self, sources, monkeypatch):
        seen = []

        def read(previous):
            seen.append(previous)
            return ("high", 70.0)

        monkeypatch.setattr(appliance_state.autostream_system_stats, "get_cpu_thermal_status", read)
        src = make_src()
        appliance_state._run_pass(src)
        appliance_state._run_pass(src)
        assert seen == ["ok", "high"]

    def test_a_dials_change_wakes_the_worker_and_the_part_follows(self, sources, monkeypatch):
        monkeypatch.setattr(appliance_state, "_PERIOD_S", 60.0)
        stop = threading.Event()
        worker = appliance_state.start(
            stop, config_path="c.ini", state_path="s.json", settings=None,
            app_version=lambda: "0.8.0")
        try:
            assert WARNINGS_PART().entries == ()
            sources["dials"] = 1
            with patch.object(appliance_state, "remove_dial_entry"):
                submit(Intent("dials.revoke", {"uuid": UUID}, Origin.USER, "webui"))
            deadline = time.monotonic() + 5.0
            while time.monotonic() < deadline and not WARNINGS_PART().entries:
                time.sleep(0.01)
            assert [e.id for e in WARNINGS_PART().entries] == ["dial_update"]
        finally:
            stop.set()
            appliance_state.poke()
            worker.join(5.0)

    @pytest.mark.parametrize("part,wakes", [
        ("playback", True), ("inputs", True), ("dials", True), ("outputs", False)])
    def test_only_some_parts_wake_the_worker(self, part, wakes):
        appliance_state._poke_event.clear()
        appliance_state._wake_on_change(state.Change(1, frozenset({part}), None, None))
        assert appliance_state._poke_event.is_set() is wakes
        appliance_state._poke_event.clear()

    def test_disabling_both_inputs_gives_no_input(self, sources):
        appliance_state._run_pass(make_src())
        FakeStore().playback(SimpleNamespace(inputs={
            1: SimpleNamespace(enabled=False), 2: SimpleNamespace(enabled=False)}))
        appliance_state._run_pass(make_src())
        assert [e.id for e in WARNINGS_PART().entries] == ["no_input"]

    def test_the_first_pass_publishes_warnings_on_the_calling_thread(self, sources):
        sources["throttled"] = 0x1
        stop = threading.Event()
        stop.set()
        worker = appliance_state.start(
            stop, config_path="c.ini", state_path="s.json", settings=None,
            app_version=lambda: "0.8.0")
        worker.join(5.0)
        assert [e.id for e in WARNINGS_PART().entries] == ["psu"]


class TestBinding:
    def test_state_refresh_and_the_dials_rows_are_bound_at_import(self):
        assert live.bound_owner("state_refresh") == "autostream_appliance_state"
        from autostream_intents import table
        assert table._table._owners["dials.authorize"] == "autostream_appliance_state"
        assert table._table._owners["dials.revoke"] == "autostream_appliance_state"


class TestDials:
    def ask(self, name, args):
        return submit(Intent(name, args, Origin.USER, "webui"))

    def test_authorize_writes_and_bumps_the_generation(self):
        with patch.object(appliance_state, "write_dial_entry") as write:
            reply = self.ask("dials.authorize", {"uuid": UUID, "name": "Kitchen"})
        assert reply.ok
        write.assert_called_once_with(UUID, "Kitchen")
        snap = state.store().snapshot()
        assert snap.dials.generation == 1
        assert reply.version == snap.version == snap.part_versions["dials"]

    def test_revoke_removes_and_bumps_the_generation(self):
        with patch.object(appliance_state, "remove_dial_entry") as remove:
            reply = self.ask("dials.revoke", {"uuid": UUID})
        assert reply.ok
        remove.assert_called_once_with(UUID)
        assert state.store().snapshot().dials.generation == 1

    def test_two_changes_are_two_generations(self):
        with patch.object(appliance_state, "remove_dial_entry"):
            self.ask("dials.revoke", {"uuid": UUID})
            self.ask("dials.revoke", {"uuid": UUID})
        assert state.store().snapshot().dials.generation == 2

    def test_the_requester_is_on_the_change(self):
        changes = []
        state.store().subscribe(changes.append)
        with patch.object(appliance_state, "remove_dial_entry"):
            self.ask("dials.revoke", {"uuid": UUID})
        mine = [c for c in changes if "dials" in c.parts]
        assert mine and mine[0].requester == "webui"

    def test_an_invalid_name_writes_nothing_and_bumps_nothing(self):
        with patch.object(appliance_state, "write_dial_entry") as write:
            reply = self.ask("dials.authorize", {"uuid": UUID, "name": "bad;name"})
        assert (reply.ok, reply.error) == (False, "invalid_name")
        write.assert_not_called()
        assert state.store().snapshot().dials.generation == 0

    def test_a_failing_write_is_internal_error_and_bumps_nothing(self):
        with patch.object(appliance_state, "write_dial_entry", side_effect=OSError("ro")):
            reply = self.ask("dials.authorize", {"uuid": UUID, "name": "Kitchen"})
        assert (reply.ok, reply.error) == (False, "internal_error")
        assert state.store().snapshot().dials.generation == 0

    @pytest.mark.parametrize("args", [{"uuid": 7}, {"uuid": ["a"]}, {"uuid": ""}, {"uuid": "x" * 65}])
    def test_a_uuid_that_is_not_bounded_text_is_invalid_args(self, args):
        with patch.object(appliance_state, "remove_dial_entry") as remove:
            reply = self.ask("dials.revoke", args)
        assert (reply.ok, reply.error) == (False, "invalid_args")
        remove.assert_not_called()
