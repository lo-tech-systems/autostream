"""tests/test_align_orchestrator.py

Unit tests for autostream_align.AlignRun, the "Align outputs" calibration
orchestrator. Uses a fake player-service, fake process-launcher, and fake
clock/sleep so the whole cycle runs deterministically and instantly.

Tests cover:
  - refuse-to-start conditions (fewer than 2 selected outputs, backend
    unreachable, already running, input actively streaming)
  - cycle order and per-window freq-file contents match cycle order
  - volume snapshot/restore, including the "0 -> 50" fallback rule
  - cleanup on error mid-cycle
  - timeout (hard cap)
  - abort() and finish() semantics (pending result, idempotent cleanup)
"""
from __future__ import annotations

import os
import sys
import tempfile
import threading
import time

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "core"))

from autostream_align import (
    AlignArrival,
    AlignResult,
    AlignRun,
    parse_result_entries,
)


# ── Fakes ──────────────────────────────────────────────────────────────────

class FakeOutput:
    def __init__(self, id, name, selected, volume_percent, offset_ms=0):
        self.id = id
        self.name = name
        self.selected = selected
        self.volume_percent = volume_percent
        self.offset_ms = offset_ms


class FakeListOutputsResult:
    def __init__(self, ok, outputs=()):
        self.ok = ok
        self.outputs = outputs
        self.error = "" if ok else "boom"


class FakePlayerService:
    def __init__(self, outputs, list_ok=True):
        self._outputs = outputs
        self._list_ok = list_ok
        self.volume_calls = []  # list of (output_id, volume_percent)

    def list_outputs(self, base_url, timeout=3):
        return FakeListOutputsResult(self._list_ok, tuple(self._outputs))

    def set_output_volume(self, base_url, output_id, volume_percent, timeout=3):
        self.volume_calls.append((output_id, volume_percent))


class FakeProc:
    """Popen-like handle the orchestrator terminates on cleanup."""

    def __init__(self):
        self.terminated = False
        self.killed = False

    def terminate(self):
        self.terminated = True

    def wait(self, timeout=None):
        return 0

    def kill(self):
        self.killed = True

    def poll(self):
        return None


class FakeLauncher:
    """Records every spawned command; spawns succeed by default."""

    def __init__(self, launch_returncode=0):
        self.calls = []
        self.launch_returncode = launch_returncode
        self.procs = []

    def __call__(self, cmd):
        self.calls.append(list(cmd))
        if self.launch_returncode != 0:
            raise RuntimeError("spawn failed")
        proc = FakeProc()
        self.procs.append(proc)
        return proc


class FakeClock:
    """A clock/sleep pair that cooperate: sleep() always advances the clock
    by the full requested duration, so hold loops resolve in one iteration
    without any real waiting."""

    def __init__(self, start=0.0):
        self.now = start
        self.sleep_calls = []

    def clock(self):
        return self.now

    def sleep(self, seconds):
        self.sleep_calls.append(seconds)
        self.now += seconds


def _make_run(outputs, list_ok=True, launch_returncode=0, freq_file=None, **kwargs):
    fake_clock = FakeClock()
    fake_launcher = FakeLauncher(launch_returncode=launch_returncode)
    player = FakePlayerService(outputs, list_ok=list_ok)
    freq_file = freq_file or tempfile.mktemp(prefix="align-freq-")
    run_kwargs = dict(
        period_ms=1000,
        cycles_per_output=1,  # hold_seconds = 1s -- resolved instantly by FakeClock
        max_seconds=600,
    )
    run_kwargs.update(kwargs)
    run = AlignRun(
        player_service=player,
        process_launcher=fake_launcher,
        clock=fake_clock.clock,
        sleep_fn=fake_clock.sleep,
        freq_file=freq_file,
        **run_kwargs,
    )
    return run, player, fake_launcher, fake_clock


def _wait_thread(run, timeout=2.0):
    thread = run._thread
    if thread is not None:
        thread.join(timeout=timeout)


# ── Refuse conditions ─────────────────────────────────────────────────────

def test_refuses_with_fewer_than_two_selected_outputs():
    outputs = [FakeOutput("a", "A", True, 30)]
    run, _, _, _ = _make_run(outputs)
    ok, err = run.start(base_url="http://localhost:3689", ret_url="http://host/align/result")
    assert ok is False
    assert "two outputs" in err


def test_refuses_when_backend_unreachable():
    run, _, _, _ = _make_run([])
    ok, err = run.start(base_url="", ret_url="http://host/align/result")
    assert ok is False
    assert "reachable" in err


def test_refuses_when_list_outputs_fails():
    outputs = [FakeOutput("a", "A", True, 30), FakeOutput("b", "B", True, 30)]
    run, _, _, _ = _make_run(outputs, list_ok=False)
    ok, err = run.start(base_url="http://localhost:3689", ret_url="http://host/align/result")
    assert ok is False


def test_refuses_when_already_running():
    # FakeClock cooperates with sleep() to resolve holds instantly, so a run
    # built on it can race through to completion/timeout in real time too
    # fast to observe "still running". Use a real clock with a hold far
    # longer than this test's own real-time budget instead.
    outputs = [FakeOutput("a", "A", True, 30), FakeOutput("b", "B", True, 30)]
    player = FakePlayerService(outputs)
    launcher = FakeLauncher()
    run = AlignRun(
        player_service=player,
        process_launcher=launcher,
        freq_file=tempfile.mktemp(prefix="align-freq-"),
        period_ms=1000,
        cycles_per_output=100000,
        max_seconds=100000,
    )
    ok, _ = run.start(base_url="http://localhost:3689", ret_url="http://host/align/result")
    assert ok is True
    time.sleep(0.05)  # let the thread reach "running" state / first hold
    ok2, err2 = run.start(base_url="http://localhost:3689", ret_url="http://host/align/result")
    assert ok2 is False
    assert "already in progress" in err2
    run.abort()


def test_refuses_when_input_actively_streaming(monkeypatch):
    import autostream_align as align_mod

    outputs = [FakeOutput("a", "A", True, 30), FakeOutput("b", "B", True, 30)]
    run, _, _, _ = _make_run(outputs)

    class FakeInput:
        active = True

    class FakeSnapshot:
        inputs = {1: FakeInput()}

    def fake_get_playback_snapshot():
        return FakeSnapshot()

    import autostream_core
    monkeypatch.setattr(autostream_core, "get_playback_snapshot", fake_get_playback_snapshot)

    ok, err = run.start(base_url="http://localhost:3689", ret_url="http://host/align/result")
    assert ok is False
    assert "streaming" in err


# ── Launch URL / frequencies ─────────────────────────────────────────────

def test_launch_url_and_frequencies_follow_cycle_order():
    outputs = [
        FakeOutput("out-a", "Living Room", True, 40),
        FakeOutput("out-b", "Kitchen", True, 0),
        FakeOutput("out-c", "Bedroom", True, 60),
    ]
    run, player, launcher, clock = _make_run(outputs, cycles_per_output=1)
    ok, launch_url = run.start(base_url="http://localhost:3689", ret_url="http://host/align/result")
    assert ok is True
    assert "outs=" in launch_url
    outs_part = launch_url.split("outs=", 1)[1]
    entries = outs_part.split(",")
    assert len(entries) == 3
    assert entries[0].startswith("out-a~1000~")
    assert entries[1].startswith("out-b~1250~")
    assert entries[2].startswith("out-c~1500~")
    assert "ret=http%3A%2F%2Fhost%2Falign%2Fresult" in launch_url
    run.abort()


def test_start_writes_freq_file_for_first_output():
    outputs = [FakeOutput("out-a", "A", True, 40), FakeOutput("out-b", "B", True, 40)]
    freq_file = tempfile.mktemp(prefix="align-freq-")
    run, player, launcher, clock = _make_run(outputs, freq_file=freq_file, cycles_per_output=1)
    ok, _ = run.start(base_url="http://localhost:3689", ret_url="http://host/align/result")
    assert ok is True
    with open(freq_file) as f:
        assert f.read().strip() == "1000"
    run.abort()


def test_all_selected_outputs_muted_before_launching_helper():
    outputs = [FakeOutput("out-a", "A", True, 40), FakeOutput("out-b", "B", True, 60)]
    run, player, launcher, clock = _make_run(outputs, cycles_per_output=1)
    run.start(base_url="http://localhost:3689", ret_url="http://host/align/result")
    # First two volume calls (before the cycle thread does anything else)
    # mute both outputs.
    assert player.volume_calls[0] == ("out-a", 0)
    assert player.volume_calls[1] == ("out-b", 0)
    run.abort()


# ── Volume snapshot / restore, incl. 0 -> 50 fallback ────────────────────

def test_zero_volume_snapshot_uses_fallback_50_during_hold():
    outputs = [FakeOutput("out-a", "A", True, 0), FakeOutput("out-b", "B", True, 30)]
    run, player, launcher, clock = _make_run(outputs, cycles_per_output=1)
    run.start(base_url="http://localhost:3689", ret_url="http://host/align/result")
    # The cycle loops forever (until stop/timeout) with FakeClock resolving
    # holds near-instantly, so a brief real sleep lets several iterations
    # happen before we stop it.
    time.sleep(0.05)
    run.abort()
    # out-a's snapshot volume was 0, so it should have been raised to 50
    # (not 0) while it was the active output.
    assert ("out-a", 50) in player.volume_calls
    assert ("out-b", 30) in player.volume_calls


def test_cleanup_restores_exact_snapshot_volumes():
    outputs = [FakeOutput("out-a", "A", True, 42), FakeOutput("out-b", "B", True, 17)]
    run, player, launcher, clock = _make_run(outputs, cycles_per_output=1)
    run.start(base_url="http://localhost:3689", ret_url="http://host/align/result")
    run.abort()
    tail = player.volume_calls[-2:]
    assert ("out-a", 42) in tail
    assert ("out-b", 17) in tail


# ── Cleanup on error mid-cycle ────────────────────────────────────────────

def test_cleanup_runs_on_error_mid_cycle():
    outputs = [FakeOutput("out-a", "A", True, 30), FakeOutput("out-b", "B", True, 30)]
    run, player, launcher, clock = _make_run(outputs, cycles_per_output=1)

    call_count = {"n": 0}
    orig_set_volume = player.set_output_volume

    def flaky_set_volume(base_url, output_id, volume_percent, timeout=3):
        call_count["n"] += 1
        if call_count["n"] == 3:
            raise RuntimeError("transport error")
        return orig_set_volume(base_url, output_id, volume_percent, timeout=timeout)

    # _set_volume already swallows exceptions from the player service, so to
    # exercise the cycle's own except-block we raise from _write_freq instead
    # (a real failure mode: e.g. /run not writable).
    orig_write_freq = run._write_freq
    write_calls = {"n": 0}

    def flaky_write_freq(freq_hz):
        write_calls["n"] += 1
        if write_calls["n"] == 2:
            raise RuntimeError("disk full")
        return orig_write_freq(freq_hz)

    run.start(base_url="http://localhost:3689", ret_url="http://host/align/result")
    run._write_freq = flaky_write_freq
    _wait_thread(run, timeout=1.0)

    status = run.status()
    assert status["state"] == "error"
    assert status["last_error"]
    # cleanup still restored volumes despite the mid-cycle failure.
    assert ("out-a", 30) in player.volume_calls
    assert ("out-b", 30) in player.volume_calls


# ── Timeout ────────────────────────────────────────────────────────────────

def test_timeout_stops_and_cleans_up():
    outputs = [FakeOutput("out-a", "A", True, 30), FakeOutput("out-b", "B", True, 30)]
    run, player, launcher, clock = _make_run(outputs, cycles_per_output=1, max_seconds=0)
    run.start(base_url="http://localhost:3689", ret_url="http://host/align/result")
    _wait_thread(run, timeout=1.0)
    status = run.status()
    assert status["state"] == "idle"
    assert "timed out" in status["last_error"]


# ── abort() / finish() ─────────────────────────────────────────────────────

def test_abort_stops_helper_and_restores_state():
    outputs = [FakeOutput("out-a", "A", True, 30), FakeOutput("out-b", "B", True, 30)]
    run, player, launcher, clock = _make_run(outputs, cycles_per_output=100)
    run.start(base_url="http://localhost:3689", ret_url="http://host/align/result")
    time.sleep(0.05)
    run.abort()
    status = run.status()
    assert status["state"] == "idle"
    assert status["has_pending_result"] is False
    assert len(launcher.procs) == 1
    assert launcher.procs[0].terminated is True


def test_finish_records_pending_result_and_stops_cycle():
    outputs = [FakeOutput("out-a", "A", True, 30), FakeOutput("out-b", "B", True, 30)]
    run, player, launcher, clock = _make_run(outputs, cycles_per_output=100)
    run.start(base_url="http://localhost:3689", ret_url="http://host/align/result")
    time.sleep(0.05)
    result = AlignResult(ref_output_id="out-a", arrivals=(AlignArrival("out-b", 12, 3),))
    run.finish(result)
    status = run.status()
    assert status["state"] == "idle"
    assert status["has_pending_result"] is True
    assert run.pending_result() is result


def test_discard_result_clears_pending():
    outputs = [FakeOutput("out-a", "A", True, 30), FakeOutput("out-b", "B", True, 30)]
    run, player, launcher, clock = _make_run(outputs, cycles_per_output=1)
    run.start(base_url="http://localhost:3689", ret_url="http://host/align/result")
    time.sleep(0.05)
    run.finish(AlignResult(ref_output_id="out-a", arrivals=()))
    assert run.pending_result() is not None
    run.discard_result()
    assert run.pending_result() is None


# ── parse_result_entries ───────────────────────────────────────────────────

def test_parse_result_entries_valid():
    arrivals = parse_result_entries("out-a~12~3,out-b~-5~40")
    assert arrivals == [
        AlignArrival("out-a", 12, 3),
        AlignArrival("out-b", -5, 40),
    ]


def test_parse_result_entries_drops_malformed_entries():
    arrivals = parse_result_entries("out-a~12~3,garbage,out-b~notanint~5,out-c~1~2")
    assert arrivals == [
        AlignArrival("out-a", 12, 3),
        AlignArrival("out-c", 1, 2),
    ]


def test_parse_result_entries_empty():
    assert parse_result_entries("") == []
    assert parse_result_entries(None) == []
