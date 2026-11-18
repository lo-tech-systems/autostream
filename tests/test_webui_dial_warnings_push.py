"""Tests for the "warnings changed" push from the appliance to its dials.

Covers:
1.  The change watcher: the first reading is a silent baseline, a change is
    pushed once, a burst inside the 10 s window is one push carrying the state
    at the window's end, a change that reverts inside the window is none, and
    a quiet set is checked every watch interval.
2.  poke() wakes the watcher loop ahead of its interval.
3.  Targets: every authorised, sighted dial at protocol generation 3 or above;
    none for an older dial, an unsighted dial, or an appliance without an
    identity.
4.  The shared push worker: one thread however many jobs, survives a failing
    job, posts {"appliance_id": id} to /warnings-changed.
5.  The watcher starts once; the service reset and config-save handlers poke it.
"""
from __future__ import annotations

import json
import sys
import threading
import time
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

REPO_ROOT = Path(__file__).parent.parent
_core = str(REPO_ROOT / "core")
if _core not in sys.path:
    sys.path.insert(0, _core)

from fake_store import fake_playback
import autostream_dial_warnings as dw
from autostream_dials import DialSighting
import autostream_dial_push as dial_push

APPLIANCE_ID = "aaaaaaaaaaaaaaaaaaaa"


class _Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


def _watcher(digests, clock):
    """A watcher whose digest is whatever digests["value"] holds."""
    notify = MagicMock()
    watcher = dw.WarningsWatcher(
        digest=lambda: digests["value"], notify=notify, clock=clock,
        watch_interval_s=30.0, min_interval_s=10.0,
    )
    return watcher, notify


class TestWatcher:
    def test_first_reading_is_a_silent_baseline(self):
        clock, digests = _Clock(), {"value": "a"}
        watcher, notify = _watcher(digests, clock)
        assert watcher.step() == 30.0
        notify.assert_not_called()

    def test_unchanged_set_is_never_pushed(self):
        clock, digests = _Clock(), {"value": "a"}
        watcher, notify = _watcher(digests, clock)
        for _ in range(5):
            watcher.step()
            clock.now += 30
        notify.assert_not_called()

    def test_a_change_is_pushed_once(self):
        clock, digests = _Clock(), {"value": "a"}
        watcher, notify = _watcher(digests, clock)
        watcher.step()
        digests["value"] = "b"
        assert watcher.step() == 30.0
        notify.assert_called_once_with()
        clock.now += 30
        watcher.step()
        notify.assert_called_once_with()

    def test_three_changes_inside_the_window_are_one_push(self):
        clock, digests = _Clock(), {"value": "a"}
        watcher, notify = _watcher(digests, clock)
        watcher.step()
        digests["value"] = "b"
        watcher.step()
        assert notify.call_count == 1
        for value in ("c", "d", "e"):
            clock.now += 1
            digests["value"] = value
            wait = watcher.step()
            assert notify.call_count == 1
            assert 0.05 <= wait <= 10.0
        clock.now += 10
        watcher.step()
        assert notify.call_count == 2
        clock.now += 30
        watcher.step()
        assert notify.call_count == 2

    def test_wait_ends_with_the_window(self):
        clock, digests = _Clock(), {"value": "a"}
        watcher, notify = _watcher(digests, clock)
        watcher.step()
        digests["value"] = "b"
        watcher.step()
        clock.now += 4
        digests["value"] = "c"
        assert watcher.step() == pytest.approx(6.0)

    def test_a_change_that_reverts_inside_the_window_is_not_pushed(self):
        clock, digests = _Clock(), {"value": "a"}
        watcher, notify = _watcher(digests, clock)
        watcher.step()
        digests["value"] = "b"
        watcher.step()
        clock.now += 2
        digests["value"] = "c"
        watcher.step()
        clock.now += 2
        digests["value"] = "b"
        watcher.step()
        clock.now += 10
        watcher.step()
        assert notify.call_count == 1

    def test_change_after_the_window_is_pushed_at_once(self):
        clock, digests = _Clock(), {"value": "a"}
        watcher, notify = _watcher(digests, clock)
        watcher.step()
        digests["value"] = "b"
        watcher.step()
        clock.now += 11
        digests["value"] = "c"
        watcher.step()
        assert notify.call_count == 2


class TestWatchLoop:
    def test_poke_wakes_the_loop_ahead_of_its_interval(self):
        steps = []
        seen = threading.Event()

        class FakeWatcher:
            def step(self):
                steps.append(time.monotonic())
                seen.set()
                return 60.0

        shutdown = threading.Event()
        dw._poke_event.clear()
        thread = threading.Thread(
            target=dw._watch_loop, args=(FakeWatcher(), shutdown), daemon=True)
        thread.start()
        assert seen.wait(2.0)
        seen.clear()
        dw.poke()
        assert seen.wait(2.0), "poke did not wake the loop"
        assert len(steps) == 2
        shutdown.set()
        dw.poke()
        thread.join(2.0)
        assert not thread.is_alive()

    def test_a_failing_step_does_not_end_the_loop(self):
        calls = []
        done = threading.Event()

        class FlakyWatcher:
            def step(self):
                calls.append(1)
                if len(calls) == 1:
                    raise RuntimeError("boom")
                done.set()
                return 60.0

        shutdown = threading.Event()
        dw._poke_event.clear()
        with patch.object(dw, "WARNINGS_WATCH_INTERVAL_S", 0.01):
            thread = threading.Thread(
                target=dw._watch_loop, args=(FlakyWatcher(), shutdown), daemon=True)
            thread.start()
            assert done.wait(2.0)
        shutdown.set()
        dw.poke()
        thread.join(2.0)

    def test_start_watcher_is_idempotent(self):
        shutdown = threading.Event()
        shutdown.set()
        with patch.object(dw, "_watcher_thread", None):
            with patch("autostream_dial_warnings.threading.Thread") as mock_thread:
                mock_thread.return_value.is_alive.return_value = True
                dw.start_watcher(shutdown)
                dw.start_watcher(shutdown)
        mock_thread.assert_called_once()
        assert mock_thread.call_args.kwargs["daemon"] is True
        mock_thread.return_value.start.assert_called_once()


def _sighting(uuid, proto):
    return DialSighting(uuid=uuid, name=uuid, version="1.0.0", ip=f"10.0.0.{len(uuid)}",
                        port=7842, pin_recovery=False, dial_proto=proto)


def _notify(entries, sightings, appliance_id=APPLIANCE_ID):
    """Run notify_dials_warnings_changed against canned stores; returns the
    enqueue_push calls."""
    with (
        patch("autostream_rpi.get_appliance_id", return_value=appliance_id),
        patch("autostream_dial_push.parse_dial_entries",
              return_value=[SimpleNamespace(uuid=u) for u in entries]),
        patch("autostream_dial_push.get_dial_sighting", side_effect=sightings.get),
        patch("autostream_dial_push.enqueue_push") as enqueue,
    ):
        dw.notify_dials_warnings_changed()
    return enqueue.call_args_list


class TestTargets:
    def test_one_push_per_sighted_authorised_v3_dial(self):
        calls = _notify(
            ["a", "bb"],
            {"a": _sighting("a", "v3"), "bb": _sighting("bb", "v4")},
        )
        assert [c.args for c in calls] == [
            ("/warnings-changed", "a", APPLIANCE_ID),
            ("/warnings-changed", "bb", APPLIANCE_ID),
        ]

    @pytest.mark.parametrize("proto", ["v2", "v1", "", "garbage"])
    def test_none_to_an_older_dial(self, proto):
        assert _notify(["a"], {"a": _sighting("a", proto)}) == []

    def test_none_to_an_unsighted_dial(self):
        assert _notify(["a"], {}) == []

    def test_none_to_a_sighted_dial_that_is_not_authorised(self):
        assert _notify([], {"stranger": _sighting("stranger", "v3")}) == []

    def test_mixed_set_pushes_only_to_the_eligible(self):
        calls = _notify(
            ["old", "new", "gone"],
            {"old": _sighting("old", "v2"), "new": _sighting("new", "v3")},
        )
        assert [c.args[1] for c in calls] == ["new"]

    def test_none_without_an_identity(self):
        assert _notify(["a"], {"a": _sighting("a", "v3")}, appliance_id=None) == []

    def test_never_raises(self):
        with patch("autostream_rpi.get_appliance_id", side_effect=RuntimeError("x")):
            dw.notify_dials_warnings_changed()


class TestEligible:
    def test_returns_the_authorised_order_less_exclusions(self):
        sightings = {u: _sighting(u, "v3") for u in ("a", "b", "c")}
        with (
            patch("autostream_dial_push.parse_dial_entries",
                  return_value=[SimpleNamespace(uuid=u) for u in ("a", "b", "c")]),
            patch("autostream_dial_push.get_dial_sighting", side_effect=sightings.get),
        ):
            assert dial_push.eligible_dial_uuids(3, exclude={"b"}) == ["a", "c"]


class TestSharedWorker:
    def test_warnings_push_body_is_the_appliance_id_only(self):
        conn = MagicMock()
        conn.getresponse.return_value = MagicMock(status=202)
        sighting = _sighting("a", "v3")
        with (
            patch("autostream_dial_push.get_dial_sighting", return_value=sighting),
            patch("autostream_dial_push.http.client.HTTPConnection", return_value=conn),
        ):
            dial_push._push_once("/warnings-changed", "a", APPLIANCE_ID)
        method, path = conn.request.call_args[0][:2]
        assert (method, path) == ("POST", "/warnings-changed")
        assert json.loads(conn.request.call_args.kwargs["body"]) == {"appliance_id": APPLIANCE_ID}

    def test_refused_connection_is_retried_once_and_never_raises(self):
        sighting = _sighting("a", "v3")
        with (
            patch("autostream_dial_push.get_dial_sighting", return_value=sighting),
            patch("autostream_dial_push.http.client.HTTPConnection",
                  side_effect=ConnectionRefusedError("refused")) as conn,
            patch("autostream_dial_push.time.sleep") as sleep,
        ):
            dial_push._push_once("/warnings-changed", "a", APPLIANCE_ID)
        assert conn.call_count == 2
        sleep.assert_called_once_with(dial_push._PUSH_RETRY_DELAY_S)

    def test_worker_survives_a_failing_job(self):
        jobs = dial_push.queue.SimpleQueue()
        handled = []
        done = threading.Event()

        def fake_push(path, uuid, appliance_id):
            handled.append(uuid)
            if uuid == "bad":
                raise RuntimeError("boom")
            done.set()

        with patch("autostream_dial_push._push_once", side_effect=fake_push):
            thread = threading.Thread(target=dial_push._push_worker_loop, args=(jobs,), daemon=True)
            thread.start()
            jobs.put(dial_push._PushJob("/warnings-changed", "bad", {"appliance_id": APPLIANCE_ID}))
            jobs.put(dial_push._PushJob("/warnings-changed", "good", {"appliance_id": APPLIANCE_ID}))
            assert done.wait(2.0)
        assert handled == ["bad", "good"]

    def test_many_jobs_use_one_thread(self):
        queue_ = dial_push.queue.SimpleQueue()
        with (
            patch.object(dial_push, "_push_queue", queue_),
            patch.object(dial_push, "_push_worker_thread", None),
            patch("autostream_dial_push.threading.Thread") as mock_thread,
        ):
            mock_thread.return_value.is_alive.return_value = True
            for i in range(5):
                dial_push.enqueue_push("/warnings-changed", f"d{i}", APPLIANCE_ID)
        mock_thread.assert_called_once()
        assert mock_thread.call_args.kwargs["daemon"] is True
        assert queue_.qsize() == 5

    def test_enqueue_never_blocks_on_the_network(self):
        queue_ = dial_push.queue.SimpleQueue()
        with (
            patch.object(dial_push, "_push_queue", queue_),
            patch.object(dial_push, "_push_worker_thread", MagicMock(is_alive=lambda: True)),
            patch("autostream_dial_push.http.client.HTTPConnection") as conn,
        ):
            dial_push.enqueue_push("/warnings-changed", "a", APPLIANCE_ID)
        conn.assert_not_called()


class TestPokeSites:
    def test_service_reset_pokes_after_a_successful_reset(self):
        import autostream_webui_api as api

        handler = MagicMock()
        with (
            patch("autostream_playback_tracking.reset_input_stylus",
                  return_value=SimpleNamespace(applied=True, persisted=True,
                                               last_service_at="stamp")),
            patch("webui.common._config_snapshot", side_effect=OSError("no config")),
            fake_playback(SimpleNamespace(inputs={})),
            patch("webui.common.send_json"),
            patch("autostream_dial_warnings.poke") as poke,
        ):
            api.send_service_reset_json(
                handler, MagicMock(), json.dumps({"item": "stylus", "input": 1}))
        poke.assert_called_once_with()

    def test_service_reset_does_not_poke_when_nothing_was_reset(self):
        import autostream_webui_api as api

        with (
            patch("autostream_playback_tracking.reset_input_stylus",
                  return_value=SimpleNamespace(applied=False, persisted=False,
                                               last_service_at=None)),
            patch("webui.common._config_snapshot", side_effect=OSError("no config")),
            patch("webui.common.send_json"),
            patch("autostream_dial_warnings.poke") as poke,
        ):
            api.send_service_reset_json(
                MagicMock(), MagicMock(), json.dumps({"item": "stylus", "input": 1}))
        poke.assert_not_called()

    def test_service_config_save_pokes(self, tmp_path):
        import autostream_webui_api as api
        from autostream_settings import SettingsStore, as_view

        cfg_path = tmp_path / "config.json"
        cfg_path.write_text("{}", encoding="utf-8")
        state = MagicMock()
        state.settings = as_view(SettingsStore(
            str(cfg_path), _save_interval_seconds=9999, _writer=MagicMock()))
        parsed = SimpleNamespace(
            audio1=SimpleNamespace(is_turntable=True, input_type="turntable",
                                   capture_device="x", stylus_life_hours=1,
                                   belt_life_hours=0, belt_life_years=0,
                                   bearing_life_hours=0, bearing_life_years=0),
            audio1_enabled=True,
        )
        with (
            patch("webui.common._config_snapshot", return_value=parsed),
            patch("autostream_playback_tracking.update_playback_input_config"),
            patch("autostream_webui_api.classify_loopback_hw", return_value="x"),
            fake_playback(SimpleNamespace(inputs={})),
            patch("webui.common.send_json"),
            patch("autostream_dial_warnings.poke") as poke,
        ):
            api.send_service_config_json(
                MagicMock(), state,
                json.dumps({"field": "service_stylus_life_hours_input1", "value": "300"}))
        poke.assert_called_once_with()
