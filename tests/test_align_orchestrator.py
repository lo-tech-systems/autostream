"""tests/test_align_orchestrator.py

Unit tests for autostream_align.AlignRun, the "Align outputs" calibration
orchestrator. Uses a fake player-service, fake process-launcher, and fake
clock/sleep so the whole cycle runs deterministically and instantly.

Tests cover:
  - refuse-to-start conditions (fewer than 2 chosen outputs, unknown output
    id, invalid volume, backend unreachable, already running, input
    actively streaming)
  - cycle order and per-window freq-file contents match cycle order
  - calibration volume (not snapshot volume) used during windows
  - chosen-but-unselected outputs get enabled, then disabled on cleanup
  - non-chosen selected outputs are muted during the run and restored after
  - volume snapshot/restore for every touched output
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
    FREQ_TABLE_HZ,
    FREQ_TABLE_MAX_HZ,
    _build_freq_table,
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
        self.enabled_calls = []  # list of (output_id, enabled)

    def list_outputs(self, base_url, timeout=3):
        return FakeListOutputsResult(self._list_ok, tuple(self._outputs))

    def set_output_volume(self, base_url, output_id, volume_percent, timeout=3):
        self.volume_calls.append((output_id, volume_percent))

    def set_output_enabled(self, base_url, output_id, enabled, timeout=3):
        self.enabled_calls.append((output_id, enabled))


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


def _start(run, outputs=None, output_ids=None, volume_percent=50,
           base_url="http://localhost:3689", ret_url="http://host/align/result"):
    ids = output_ids if output_ids is not None else [o.id for o in outputs]
    return run.start(base_url=base_url, ret_url=ret_url, output_ids=ids, volume_percent=volume_percent)


# ── Refuse conditions ─────────────────────────────────────────────────────

def test_refuses_with_fewer_than_two_chosen_outputs():
    outputs = [FakeOutput("a", "A", True, 30)]
    run, _, _, _ = _make_run(outputs)
    ok, err = _start(run, outputs)
    assert ok is False
    assert "two outputs" in err


def test_refuses_when_backend_unreachable():
    run, _, _, _ = _make_run([])
    ok, err = run.start(base_url="", ret_url="http://host/align/result", output_ids=["a", "b"], volume_percent=50)
    assert ok is False
    assert "reachable" in err


def test_refuses_with_unknown_output_id():
    outputs = [FakeOutput("a", "A", True, 30), FakeOutput("b", "B", True, 30)]
    run, _, _, _ = _make_run(outputs)
    ok, err = _start(run, output_ids=["a", "nope"])
    assert ok is False
    assert "Unknown output" in err


def test_refuses_with_invalid_volume():
    outputs = [FakeOutput("a", "A", True, 30), FakeOutput("b", "B", True, 30)]
    run, _, _, _ = _make_run(outputs)
    ok, err = _start(run, outputs, volume_percent=0)
    assert ok is False
    assert "volume" in err.lower()


def test_refuses_when_list_outputs_fails():
    outputs = [FakeOutput("a", "A", True, 30), FakeOutput("b", "B", True, 30)]
    run, _, _, _ = _make_run(outputs, list_ok=False)
    ok, err = _start(run, outputs)
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
    ok, _ = _start(run, outputs)
    assert ok is True
    time.sleep(0.05)  # let the thread reach "running" state / first hold
    ok2, err2 = _start(run, outputs)
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

    ok, err = _start(run, outputs)
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
    ok, launch_url = _start(run, outputs)
    assert ok is True
    assert "outs=" in launch_url
    outs_part = launch_url.split("outs=", 1)[1]
    entries = outs_part.split(",")
    assert len(entries) == 3
    assert entries[0].startswith("out-a~600~")
    assert entries[1].startswith("out-b~840~")
    assert entries[2].startswith("out-c~1450~")
    assert "ret=http%3A%2F%2Fhost%2Falign%2Fresult" in launch_url
    run.abort()


def test_start_writes_freq_file_for_first_output():
    outputs = [FakeOutput("out-a", "A", True, 40), FakeOutput("out-b", "B", True, 40)]
    freq_file = tempfile.mktemp(prefix="align-freq-")
    run, player, launcher, clock = _make_run(outputs, freq_file=freq_file, cycles_per_output=1)
    ok, _ = _start(run, outputs)
    assert ok is True
    with open(freq_file) as f:
        assert f.read().strip() == "600"
    run.abort()


def test_all_selected_outputs_muted_before_launching_helper():
    outputs = [FakeOutput("out-a", "A", True, 40), FakeOutput("out-b", "B", True, 60)]
    run, player, launcher, clock = _make_run(outputs, cycles_per_output=1)
    _start(run, outputs)
    # First two volume calls (before the cycle thread does anything else)
    # mute both outputs.
    assert player.volume_calls[0] == ("out-a", 0)
    assert player.volume_calls[1] == ("out-b", 0)
    run.abort()


# ── Volume during windows / snapshot restore ──────────────────────────────

def test_calibration_volume_used_during_hold_not_snapshot_volume():
    outputs = [FakeOutput("out-a", "A", True, 5), FakeOutput("out-b", "B", True, 30)]
    run, player, launcher, clock = _make_run(outputs, cycles_per_output=1)
    _start(run, outputs, volume_percent=77)
    # The cycle loops forever (until stop/timeout) with FakeClock resolving
    # holds near-instantly, so a brief real sleep lets several iterations
    # happen before we stop it.
    time.sleep(0.05)
    run.abort()
    # Both outputs are soloed at the calibration volume passed to start(),
    # not at their own snapshot volume.
    assert ("out-a", 77) in player.volume_calls
    assert ("out-b", 77) in player.volume_calls


def test_cleanup_restores_exact_snapshot_volumes():
    outputs = [FakeOutput("out-a", "A", True, 42), FakeOutput("out-b", "B", True, 17)]
    run, player, launcher, clock = _make_run(outputs, cycles_per_output=1)
    _start(run, outputs)
    run.abort()
    tail = player.volume_calls[-2:]
    assert ("out-a", 42) in tail
    assert ("out-b", 17) in tail


def test_non_chosen_selected_output_is_muted_and_restored():
    outputs = [
        FakeOutput("out-a", "A", True, 40),
        FakeOutput("out-b", "B", True, 60),
        FakeOutput("out-c", "C", True, 25),  # selected but not chosen
    ]
    run, player, launcher, clock = _make_run(outputs, cycles_per_output=1)
    _start(run, output_ids=["out-a", "out-b"])
    # out-c was never chosen and never enabled, so it's never re-enabled --
    # but it was selected, so it gets muted for the duration of the run.
    assert ("out-c", 0) in player.volume_calls
    assert not any(oid == "out-c" for oid, _ in player.enabled_calls)
    run.abort()
    # ...and restored to its original volume on cleanup.
    assert ("out-c", 25) in player.volume_calls[-3:]


def test_chosen_unselected_output_enabled_then_disabled_on_cleanup():
    outputs = [
        FakeOutput("out-a", "A", True, 40),
        FakeOutput("out-b", "B", False, 60),  # chosen but not currently selected
    ]
    run, player, launcher, clock = _make_run(outputs, cycles_per_output=1)
    _start(run, output_ids=["out-a", "out-b"])
    assert ("out-b", True) in player.enabled_calls
    run.abort()
    assert ("out-b", False) in player.enabled_calls
    # out-a was already selected, so the run never touches its selection.
    assert not any(oid == "out-a" for oid, _ in player.enabled_calls)


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

    _start(run, outputs)
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
    _start(run, outputs)
    _wait_thread(run, timeout=1.0)
    status = run.status()
    assert status["state"] == "idle"
    assert "timed out" in status["last_error"]


# ── abort() / finish() ─────────────────────────────────────────────────────

def test_abort_stops_helper_and_restores_state():
    outputs = [FakeOutput("out-a", "A", True, 30), FakeOutput("out-b", "B", True, 30)]
    run, player, launcher, clock = _make_run(outputs, cycles_per_output=100)
    _start(run, outputs)
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
    _start(run, outputs)
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
    _start(run, outputs)
    time.sleep(0.05)
    run.finish(AlignResult(ref_output_id="out-a", arrivals=()))
    assert run.pending_result() is not None
    run.discard_result()
    assert run.pending_result() is None


# ── Frequency table ────────────────────────────────────────────────────────

def test_freq_table_uses_fixed_entries_within_table_size():
    assert _build_freq_table(len(FREQ_TABLE_HZ)) == list(FREQ_TABLE_HZ)


def test_freq_table_extends_beyond_fixed_entries():
    freqs = _build_freq_table(len(FREQ_TABLE_HZ) + 1)
    assert freqs[: len(FREQ_TABLE_HZ)] == list(FREQ_TABLE_HZ)
    # Extension multiplies the previous entry (4600) by 1.45, rounded to 10Hz.
    assert freqs[len(FREQ_TABLE_HZ)] == 6670
    assert all(f <= FREQ_TABLE_MAX_HZ for f in freqs)


def test_freq_table_refuses_when_extension_would_exceed_cap():
    # 6 fixed entries extend to a 7th (6670Hz) within the cap, but the 8th
    # extension step (9670Hz) exceeds FREQ_TABLE_MAX_HZ (8000), so 9
    # distinct frequencies cannot be produced.
    assert _build_freq_table(len(FREQ_TABLE_HZ) + 1) is not None
    assert _build_freq_table(len(FREQ_TABLE_HZ) + 2) is None


def test_start_refuses_when_too_many_outputs_for_frequency_table(monkeypatch):
    import autostream_align as align_mod

    monkeypatch.setattr(align_mod, "_build_freq_table", lambda n: None)
    outputs = [FakeOutput("a", "A", True, 30), FakeOutput("b", "B", True, 30)]
    run, _, _, _ = _make_run(outputs)
    ok, err = _start(run, outputs)
    assert ok is False
    assert "Too many outputs" in err


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


# ── Pipe-format probe robustness ──────────────────────────────────────────

class _FailingGetSettingService(FakePlayerService):
    def get_setting(self, base_url, key, timeout=3):
        raise RuntimeError("backend hiccup")


class _UnsupportedGetSettingService(FakePlayerService):
    class _Result:
        ok = False
        unsupported = True
        value = None

    def get_setting(self, base_url, key, timeout=3):
        return self._Result()


def test_refuses_when_pipe_format_probe_fails_transiently():
    outputs = [FakeOutput("a", "A", True, 30), FakeOutput("b", "B", True, 30)]
    player = _FailingGetSettingService(outputs)
    run = AlignRun(
        player_service=player,
        process_launcher=FakeLauncher(),
        clock=FakeClock().clock,
        sleep_fn=lambda s: None,
        freq_file=tempfile.mktemp(prefix="align-freq-"),
    )
    ok, err = run.start(base_url="http://localhost:3689", ret_url="http://host/align/result",
                        output_ids=["a", "b"], volume_percent=50)
    assert ok is False
    assert "stream format" in err


def test_falls_back_when_pipe_format_unsupported():
    outputs = [FakeOutput("a", "A", True, 30), FakeOutput("b", "B", True, 30)]
    player = _UnsupportedGetSettingService(outputs)
    run = AlignRun(
        player_service=player,
        process_launcher=FakeLauncher(),
        clock=FakeClock().clock,
        sleep_fn=lambda s: None,
        freq_file=tempfile.mktemp(prefix="align-freq-"),
    )
    ok, _ = run.start(base_url="http://localhost:3689", ret_url="http://host/align/result",
                      output_ids=["a", "b"], volume_percent=50)
    assert ok is True
    run.abort()
