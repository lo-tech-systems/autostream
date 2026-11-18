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
from unittest.mock import patch

import pytest

_CORE = str(Path(__file__).resolve().parent.parent / "core")
if _CORE not in sys.path:
    sys.path.insert(0, _CORE)

import autostream_appliance_state as appliance_state
import autostream_state as state
from autostream_intents import Intent, Origin, submit
from autostream_state import live

UUID = "0123456789abcdef0123"


@pytest.fixture
def sources(monkeypatch):
    """Every source the appliance part reads, as plain values the test sets."""
    values = {
        "id": "aa11bb22cc33dd44ee55", "host": "Turntable.local", "version": "0.8.0",
        "commissioning": False, "pin": True,
    }
    monkeypatch.setattr(appliance_state.rpi, "get_appliance_id", lambda: values["id"])
    monkeypatch.setattr(appliance_state, "get_system_hostname", lambda: values["host"])
    monkeypatch.setattr(appliance_state, "is_commissioning_required",
                        lambda config, st: values["commissioning"])
    monkeypatch.setattr(appliance_state, "pin_is_set", lambda st: values["pin"])
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


class TestBinding:
    def test_state_refresh_and_the_dials_rows_are_bound_at_import(self):
        assert live.bound_owner("state_refresh") == "autostream_appliance_state"
        from autostream_intents import table
        assert table._table._owners["dials.authorize"] == "autostream_appliance_state"
        assert table._table._owners["dials.revoke"] == "autostream_appliance_state"


class TestDials:
    def ask(self, name, args):
        return submit(Intent(name, args, Origin.USER, "webui"))

    def test_authorize_writes_bumps_the_generation_and_pushes(self):
        with patch.object(appliance_state, "write_dial_entry") as write, \
             patch.object(appliance_state, "notify_dial_auth_changed") as push:
            reply = self.ask("dials.authorize", {"uuid": UUID, "name": "Kitchen"})
        assert reply.ok
        write.assert_called_once_with(UUID, "Kitchen")
        push.assert_called_once_with(UUID)
        snap = state.store().snapshot()
        assert snap.dials.generation == 1
        assert reply.version == snap.version == snap.part_versions["dials"]

    def test_revoke_removes_bumps_and_pushes(self):
        with patch.object(appliance_state, "remove_dial_entry") as remove, \
             patch.object(appliance_state, "notify_dial_auth_changed") as push:
            reply = self.ask("dials.revoke", {"uuid": UUID})
        assert reply.ok
        remove.assert_called_once_with(UUID)
        push.assert_called_once_with(UUID)
        assert state.store().snapshot().dials.generation == 1

    def test_two_changes_are_two_generations(self):
        with patch.object(appliance_state, "remove_dial_entry"), \
             patch.object(appliance_state, "notify_dial_auth_changed"):
            self.ask("dials.revoke", {"uuid": UUID})
            self.ask("dials.revoke", {"uuid": UUID})
        assert state.store().snapshot().dials.generation == 2

    def test_the_requester_is_on_the_change(self):
        changes = []
        state.store().subscribe(changes.append)
        with patch.object(appliance_state, "remove_dial_entry"), \
             patch.object(appliance_state, "notify_dial_auth_changed"):
            self.ask("dials.revoke", {"uuid": UUID})
        mine = [c for c in changes if "dials" in c.parts]
        assert mine and mine[0].requester == "webui"

    def test_an_invalid_name_writes_nothing_and_bumps_nothing(self):
        with patch.object(appliance_state, "write_dial_entry") as write, \
             patch.object(appliance_state, "notify_dial_auth_changed") as push:
            reply = self.ask("dials.authorize", {"uuid": UUID, "name": "bad;name"})
        assert (reply.ok, reply.error) == (False, "invalid_name")
        write.assert_not_called()
        push.assert_not_called()
        assert state.store().snapshot().dials.generation == 0

    def test_a_failing_write_is_internal_error_and_bumps_nothing(self):
        with patch.object(appliance_state, "write_dial_entry", side_effect=OSError("ro")), \
             patch.object(appliance_state, "notify_dial_auth_changed") as push:
            reply = self.ask("dials.authorize", {"uuid": UUID, "name": "Kitchen"})
        assert (reply.ok, reply.error) == (False, "internal_error")
        push.assert_not_called()
        assert state.store().snapshot().dials.generation == 0

    def test_a_push_that_raises_does_not_fail_the_reply(self):
        with patch.object(appliance_state, "remove_dial_entry"), \
             patch.object(appliance_state, "notify_dial_auth_changed", side_effect=RuntimeError("x")):
            reply = self.ask("dials.revoke", {"uuid": UUID})
        assert reply.ok

    @pytest.mark.parametrize("args", [{"uuid": 7}, {"uuid": ["a"]}, {"uuid": ""}, {"uuid": "x" * 65}])
    def test_a_uuid_that_is_not_bounded_text_is_invalid_args(self, args):
        with patch.object(appliance_state, "remove_dial_entry") as remove:
            reply = self.ask("dials.revoke", args)
        assert (reply.ok, reply.error) == (False, "invalid_args")
        remove.assert_not_called()
