"""tests/test_align_intents.py

The calibration run behind its intent rows: what each row accepts and
refuses, the run's status and review as live reads, and that no lock of the
run is held while it talks to the player or waits.
"""
from __future__ import annotations

import json
import sys
import threading
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

_TESTS = Path(__file__).resolve().parent
_CORE = str(_TESTS.parent / "core")
for _p in (_CORE, str(_TESTS)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import autostream_align
import autostream_core  # noqa: F401  (binds the intent handlers)
from autostream_align import AlignArrival, AlignOutputSnapshot, AlignResult
from autostream_intents import Intent, Origin, submit
from autostream_settings import SettingsStore, as_view
from autostream_state import live
from test_align_orchestrator import FakeLauncher, FakeOutput, FakePlayerService, _make_run


@pytest.fixture(autouse=True)
def _keep_the_process_run():
    saved = autostream_align._RUN
    yield
    autostream_align._RUN = saved


@pytest.fixture
def ctx(tmp_path):
    path = tmp_path / "config.json"
    path.write_text(json.dumps({"owntone": {"base_url": "http://player:3689"}}), encoding="utf-8")
    store = SettingsStore(str(path), _save_interval_seconds=9999, _writer=MagicMock())
    yield SimpleNamespace(settings=as_view(store), config_path=str(path))
    store.close(save=False)


def _start(ctx, **args):
    args.setdefault("output_ids", ["a", "b"])
    args.setdefault("volume", 50)
    args.setdefault("ret_url", "http://host/align/result")
    return submit(Intent("align.start", args, Origin.USER, "webui", context=ctx))


def _outputs():
    return [FakeOutput("a", "A", True, 30), FakeOutput("b", "B", True, 40)]


# ------------------------------------------------------------------ align.start

def test_start_hands_the_run_its_values_and_the_configured_player(ctx):
    run = MagicMock()
    run.start.return_value = (True, "https://example.test/launch")
    autostream_align._RUN = run
    reply = _start(ctx, output_ids=["a", "b"], volume=65)
    assert (reply.ok, dict(reply.result)) == (True, {"launch_url": "https://example.test/launch"})
    run.start.assert_called_once_with(
        base_url="http://player:3689", ret_url="http://host/align/result",
        output_ids=["a", "b"], volume_percent=65)


def test_start_passes_the_runs_refusal_on(ctx):
    run = MagicMock()
    run.start.return_value = (False, "A calibration run is already in progress")
    autostream_align._RUN = run
    reply = _start(ctx)
    assert (reply.ok, reply.error) == (False, "A calibration run is already in progress")


def test_start_without_a_configured_player_is_refused_by_the_run(tmp_path):
    path = tmp_path / "config.json"
    path.write_text(json.dumps({"owntone": {"base_url": ""}}), encoding="utf-8")
    store = SettingsStore(str(path), _save_interval_seconds=9999, _writer=MagicMock())
    try:
        run, _, _, _ = _make_run(_outputs())
        autostream_align._RUN = run
        reply = _start(SimpleNamespace(settings=as_view(store), config_path=str(path)))
    finally:
        store.close(save=False)
    assert (reply.ok, reply.error) == (False, "OwnTone backend is not reachable")


def test_start_falls_back_to_the_configuration_file_without_a_store(tmp_path):
    path = tmp_path / "config.json"
    path.write_text(json.dumps({"owntone": {"base_url": "http://file:3689"}}), encoding="utf-8")
    run = MagicMock()
    run.start.return_value = (True, "u")
    autostream_align._RUN = run
    assert _start(SimpleNamespace(settings=None, config_path=str(path))).ok is True
    assert run.start.call_args.kwargs["base_url"] == "http://file:3689"


@pytest.mark.parametrize("args, error", [
    ({"output_ids": ["a"]}, "output_ids must list at least two outputs"),
    ({"output_ids": ["a", " "]}, "output_ids must list at least two outputs"),
    ({"output_ids": "ab"}, "output_ids must list at least two outputs"),
    ({"output_ids": ["x" * 65, "b"]}, "output_ids must list at least two outputs"),
    ({"volume": 0}, "volume must be a whole number between 1 and 100"),
    ({"volume": True}, "volume must be a whole number between 1 and 100"),
    ({"volume": 101}, "volume must be a whole number between 1 and 100"),
])
def test_start_refuses_bad_arguments_before_the_run(ctx, args, error):
    run = MagicMock()
    autostream_align._RUN = run
    reply = _start(ctx, **args)
    assert (reply.ok, reply.error) == (False, error)
    run.start.assert_not_called()


def test_the_rows_are_for_users_only(ctx):
    for name, args in (("align.start", {"output_ids": ["a", "b"], "volume": 5, "ret_url": "u"}),
                       ("align.abort", {}), ("align.discard", {}), ("align.finish", {"ref": ""})):
        reply = submit(Intent(name, args, Origin.SYSTEM, "coordinator", context=ctx))
        assert reply.error == "origin_not_allowed", name


# ------------------------------------------------- abort, finish and discard

def test_abort_and_discard_reach_the_run(ctx):
    run = MagicMock()
    autostream_align._RUN = run
    assert submit(Intent("align.abort", {}, Origin.USER, "webui")).ok is True
    assert submit(Intent("align.discard", {}, Origin.USER, "webui")).ok is True
    run.abort.assert_called_once_with()
    run.discard_result.assert_called_once_with()


def test_finish_keeps_the_measurement_as_the_pending_result():
    run = MagicMock()
    autostream_align._RUN = run
    reply = submit(Intent("align.finish", {"ref": "a", "arrivals": (("b", -12, 3), ("c", 4, 41))},
                          Origin.USER, "webui"))
    assert reply.ok is True
    run.finish.assert_called_once_with(AlignResult(
        ref_output_id="a",
        arrivals=(AlignArrival("b", -12, 3), AlignArrival("c", 4, 41))))


def test_finish_with_an_empty_ref_stops_the_run_and_keeps_nothing():
    run = MagicMock()
    autostream_align._RUN = run
    assert submit(Intent("align.finish", {"ref": ""}, Origin.USER, "webui")).ok is True
    run.finish.assert_called_once_with(None)


# ---------------------------------------------------------------- live reads

def test_the_live_reads_report_the_process_run():
    run = MagicMock()
    run.status.return_value = {"state": "idle"}
    snap = AlignOutputSnapshot(id="a", name="A", volume_percent=30, stored_offset_ms=0, freq_hz=600)
    pending = AlignResult(ref_output_id="a")
    run.snapshots.return_value = [snap]
    run.pending_result.return_value = pending
    autostream_align._RUN = run
    assert live.get_align_status() == {"state": "idle"}
    review = live.get_align_review()
    assert review == autostream_align.AlignReview((snap,), pending)


def test_reset_for_tests_replaces_the_run():
    before = autostream_align._RUN
    autostream_align.reset_for_tests()
    assert autostream_align._RUN is not before
    assert live.get_align_status()["state"] == "idle"


# ------------------------------------------------- no lock across slow calls

class _LockProbe:
    """Wraps a player so each call checks, from another thread, that the
    run's lock is free while the call is in progress."""

    def __init__(self, player, run):
        self._player = player
        self._run = run
        self.free_during_calls = []

    def _probe(self):
        got = []

        def attempt():
            acquired = self._run._lock.acquire(timeout=1.0)
            got.append(acquired)
            if acquired:
                self._run._lock.release()

        t = threading.Thread(target=attempt)
        t.start()
        t.join()
        self.free_during_calls.append(got[0])

    def set_output_volume(self, *args, **kwargs):
        self._probe()
        return self._player.set_output_volume(*args, **kwargs)

    def set_output_enabled(self, *args, **kwargs):
        self._probe()
        return self._player.set_output_enabled(*args, **kwargs)


def test_the_runs_lock_is_free_during_player_calls_and_the_stop_wait(ctx, tmp_path):
    # A real clock and a long hold, so the run is still going when it is read.
    player = FakePlayerService(_outputs())
    run = autostream_align.AlignRun(
        player_service=player,
        process_launcher=FakeLauncher(),
        freq_file=str(tmp_path / "align-freq"),
        period_ms=1000,
        cycles_per_output=100000,
        max_seconds=100000,
    )
    probe = _LockProbe(player, run)
    run._player_service = probe
    autostream_align._RUN = run

    reply = _start(ctx)
    assert reply.ok is True
    # Reads from another thread are not held up while the run is going.
    assert live.get_align_status()["state"] == "running"
    assert submit(Intent("align.abort", {}, Origin.USER, "webui")).ok is True

    assert probe.free_during_calls and all(probe.free_during_calls)
    assert live.get_align_status()["state"] == "idle"
