#!/usr/bin/env python3
"""autostream_align.py

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.

Orchestrator for the "Align outputs" calibration feature. Cycles a tone
burst through each selected AirPlay output in turn -- by muting every
selected output and raising one at a time, outputs stay connected the whole
time -- so a companion phone page (hosted elsewhere, not part of this
appliance) can measure arrival phase and hand per-output offsets back via a
plain GET navigation to /align/result.

Contents:
  - AlignOutputSnapshot -- one output's captured id/name/volume/offset/freq
  - AlignArrival        -- one parsed entry from the /align/result handoff
  - AlignResult          -- the full parsed handoff (ref + arrivals)
  - parse_result_entries -- parser for the 'data' query parameter
  - AlignRun             -- run lifecycle: start/abort/finish/cleanup/status
"""

from __future__ import annotations

import logging
import os
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Optional
from urllib.parse import quote, unquote

_log = logging.getLogger(__name__)

# ---- Protocol v1 fixed contract (see autostream_align_tone.py for the tone
# helper side of this contract; do not change these without updating both).
# Lives in the service's own runtime directory: the appliance process runs
# as an unprivileged user that cannot create new directories under /run.
FREQ_FILE = "/run/autostream-pipes/align-freq"
TONE_HELPER = "/opt/autostream/autostream_align_tone.py"
PERIOD_MS = 1500
BURST_MS = 150
CYCLES_PER_OUTPUT = 5  # k in the launch URL; hold time per output = k * period
# Fixed table rather than a linear ramp: each tone sits at least ~200Hz clear
# of the 2nd and 3rd harmonics of every lower tone in the table, so a
# distorted small speaker's harmonics don't land in another output's
# detection bin and cause misattribution. Assignment is by cycle-order index;
# more outputs than entries extends the table (see _freq_for_index).
FREQ_TABLE_HZ = (600, 840, 1450, 2100, 3100, 4600)
FREQ_TABLE_EXTEND_FACTOR = 1.45
FREQ_TABLE_MAX_HZ = 8000
MAX_SECONDS = 600  # hard cap on a whole run, regardless of cycle count
# The tone helper must generate at the rate the backend actually reads the
# pipe at, or every burst shifts in pitch AND the audible period stretches
# away from the p the phone page was told, breaking its phase clustering.
# The live rate is probed from the backend at start(); the fallback covers
# backends whose pipe rate is not API-readable, which consume 44100.
FALLBACK_TONE_RATE_HZ = 44100
FALLBACK_TONE_BITS = 16
TONE_CHANNELS = 2

_POLL_INTERVAL_S = 0.5

LAUNCH_HOST = "https://lo-tech.co.uk/as-api/autoalign/"


@dataclass(frozen=True)
class AlignOutputSnapshot:
    id: str
    name: str
    volume_percent: int
    stored_offset_ms: int
    freq_hz: int
    selected: bool = False


@dataclass(frozen=True)
class AlignArrival:
    output_id: str
    delta_ms: int
    spread_ms: int


@dataclass(frozen=True)
class AlignResult:
    ref_output_id: str
    arrivals: tuple = ()


def _build_freq_table(count: int) -> "Optional[list]":
    """Frequencies for *count* participants, by cycle-order index.

    Starts from the fixed FREQ_TABLE_HZ; if more frequencies are needed than
    the table holds, extends it by repeatedly multiplying the last entry by
    FREQ_TABLE_EXTEND_FACTOR and rounding to the nearest 10Hz. Returns None
    if the extension would need to exceed FREQ_TABLE_MAX_HZ before *count*
    frequencies are available -- there is no more room to keep tones clear
    of each other's harmonics.
    """
    freqs = list(FREQ_TABLE_HZ)
    while len(freqs) < count:
        nxt = round((freqs[-1] * FREQ_TABLE_EXTEND_FACTOR) / 10.0) * 10
        if nxt > FREQ_TABLE_MAX_HZ:
            return None
        freqs.append(nxt)
    return freqs[:count]


def parse_result_entries(raw: str) -> list:
    """Parse the 'data' query parameter into AlignArrival entries.

    Each entry is '<urlencoded id>~<delta_ms>~<spread_ms>'. Malformed
    entries (wrong field count, empty id, non-integer delta/spread) are
    dropped individually rather than failing the whole parse -- one bad
    entry from a flaky phone page shouldn't discard every other output's
    measurement.
    """
    arrivals: list = []
    for chunk in (raw or "").split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        parts = chunk.split("~")
        if len(parts) != 3:
            continue
        oid_raw, delta_raw, spread_raw = parts
        oid = unquote(oid_raw).strip()
        if not oid:
            continue
        try:
            delta_ms = int(delta_raw)
            spread_ms = int(spread_raw)
        except ValueError:
            continue
        arrivals.append(AlignArrival(output_id=oid, delta_ms=delta_ms, spread_ms=spread_ms))
    return arrivals


class AlignRun:
    """Owns the lifecycle of one calibration run.

    A single instance lives on WebUIState (state.align_run) for the life of
    the process. Not re-entrant across runs -- start() refuses while a run
    is already active.
    """

    def __init__(
        self,
        *,
        player_service=None,
        process_launcher: Optional[Callable[[list], "subprocess.CompletedProcess"]] = None,
        clock: Optional[Callable[[], float]] = None,
        sleep_fn: Optional[Callable[[float], None]] = None,
        freq_file: str = FREQ_FILE,
        period_ms: int = PERIOD_MS,
        cycles_per_output: int = CYCLES_PER_OUTPUT,
        max_seconds: int = MAX_SECONDS,
        poll_interval_s: float = _POLL_INTERVAL_S,
    ) -> None:
        if player_service is None:
            import autostream_player_service as player_service  # local default
        self._player_service = player_service
        self._launch = process_launcher or subprocess.Popen
        self._helper_proc = None
        self._clock = clock or time.monotonic
        self._sleep = sleep_fn or time.sleep
        self._freq_file = freq_file
        self._period_ms = period_ms
        self._cycles_per_output = cycles_per_output
        self._hold_seconds = cycles_per_output * (period_ms / 1000.0)
        self._max_seconds = max_seconds
        self._poll_interval_s = poll_interval_s

        self._lock = threading.RLock()
        self._state = "idle"  # idle | running | finishing | error
        self._snapshots: list = []  # every available output, for restore
        self._participants: list = []  # chosen outputs only, in cycle order
        self._touched_ids: list = []  # outputs muted this run (volume restore), in mute order
        self._enabled_ids: list = []  # outputs this run enabled (disable on cleanup)
        self._volume_percent = 0
        self._base_url = ""
        self._started_at = 0.0
        self._cycle_count = 0
        self._current_index = 0
        self._last_error = ""
        self._launch_url = ""
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._pending_result: Optional[AlignResult] = None
        self._tone_rate = FALLBACK_TONE_RATE_HZ
        self._tone_bits = FALLBACK_TONE_BITS
        self._guard_seconds = 3.5  # recomputed at start() from the live stream latency

    # -- start ----------------------------------------------------------------

    def start(
        self, *, base_url: str, ret_url: str, output_ids: list, volume_percent: int
    ) -> "tuple[bool, str]":
        """Attempt to start a run. Returns (ok, error_message_or_launch_url)."""
        with self._lock:
            if self._state in ("running", "finishing"):
                return False, "A calibration run is already in progress"
            if not base_url:
                return False, "OwnTone backend is not reachable"

        ids = list(output_ids or [])
        if len(ids) < 2:
            return False, "Select at least two outputs before calibrating"
        if not isinstance(volume_percent, int) or not (1 <= volume_percent <= 100):
            return False, "Invalid calibration volume"

        if self._input_actively_streaming():
            return False, "Cannot calibrate while an input is actively streaming"

        outputs_result = self._player_service.list_outputs(base_url, timeout=3)
        if not outputs_result.ok:
            return False, "Could not list outputs"
        all_outputs = list(outputs_result.outputs)
        by_id = {out.id: out for out in all_outputs}

        unknown = [oid for oid in ids if oid not in by_id]
        if unknown:
            return False, f"Unknown output: {unknown[0]}"

        freqs = _build_freq_table(len(ids))
        if freqs is None:
            return False, "Too many outputs selected to assign distinct calibration tones"

        # Snapshot every available output (not just the chosen ones) so
        # cleanup() can restore selection/volume for anything the run
        # touches, including outputs that were selected but not chosen.
        snapshots = [
            AlignOutputSnapshot(
                id=out.id,
                name=out.name,
                volume_percent=int(out.volume_percent or 0),
                stored_offset_ms=int(out.offset_ms or 0),
                freq_hz=0,
                selected=bool(getattr(out, "selected", False)),
            )
            for out in all_outputs
        ]
        participants = [
            AlignOutputSnapshot(
                id=by_id[oid].id,
                name=by_id[oid].name,
                volume_percent=int(by_id[oid].volume_percent or 0),
                stored_offset_ms=int(by_id[oid].offset_ms or 0),
                freq_hz=freqs[i],
                selected=bool(getattr(by_id[oid], "selected", False)),
            )
            for i, oid in enumerate(ids)
        ]

        selected_ids = {out.id for out in all_outputs if getattr(out, "selected", False)}
        chosen_ids = set(ids)
        to_enable = [oid for oid in ids if oid not in selected_ids]
        # Deterministic order (chosen first, then remaining selected): sets
        # would mute in hash order, which varies run to run.
        touched_ids = list(ids) + [
            out.id for out in all_outputs
            if out.id in selected_ids and out.id not in chosen_ids
        ]

        launch_url = self._build_launch_url(participants, ret_url)
        pipe_format = self._probe_pipe_format(base_url)
        if pipe_format is None:
            return False, "Could not read the player's stream format; please try again"
        self._tone_rate, self._tone_bits = pipe_format
        self._guard_seconds = self._compute_guard_seconds(base_url)

        try:
            self._write_freq(participants[0].freq_hz)
        except Exception:
            _log.exception("AlignRun.start: could not write freq file")
            return False, "Could not prepare calibration"

        # Outputs the caller chose but that weren't already selected must be
        # enabled before they can carry the tone. Every touched output
        # (chosen or already selected) is then muted -- volume 0 is a true
        # mute at the receiver, so nothing audible plays until its window.
        for oid in to_enable:
            self._set_enabled(base_url, oid, True)
        for oid in touched_ids:
            self._set_volume(base_url, oid, 0)

        try:
            self._launch_helper()
        except Exception:
            _log.exception("AlignRun.start: could not launch tone helper")
            self._base_url = base_url
            self._snapshots = snapshots
            self._touched_ids = touched_ids
            self._enabled_ids = list(to_enable)
            self.cleanup()
            return False, "Could not start tone generator"

        with self._lock:
            self._base_url = base_url
            self._snapshots = snapshots
            self._participants = participants
            self._touched_ids = touched_ids
            self._enabled_ids = list(to_enable)
            self._volume_percent = volume_percent
            self._launch_url = launch_url
            self._state = "running"
            self._started_at = self._clock()
            self._cycle_count = 0
            self._current_index = 0
            self._last_error = ""
            self._pending_result = None
            self._stop_event = threading.Event()
            thread = threading.Thread(target=self._run_cycle, daemon=True, name="align-cycle")
            self._thread = thread
        thread.start()

        return True, launch_url

    def _input_actively_streaming(self) -> bool:
        """Best-effort check that nothing is actively streaming right now.

        Uses the existing playback-activity tracker; any failure to read it
        (tracker not initialised, import error) is treated as "not
        streaming" rather than blocking the feature -- there is no other
        cheap hook for this today.
        """
        try:
            from autostream_core import get_playback_snapshot
            snap = get_playback_snapshot()
            return any(getattr(i, "active", False) for i in snap.inputs.values())
        except Exception:
            _log.debug("AlignRun: playback activity check unavailable", exc_info=True)
            return False

    def _probe_pipe_format(self, base_url: str) -> "Optional[tuple[int, int]]":
        """The (rate, bits) the backend reads the pipe at right now. Both
        must match exactly - a mismatch makes the consumer read the stream
        at the wrong frame rate, starving playback with garbled audio, so a
        TRANSIENT probe failure returns None and the run must not start on
        a guess. A backend that reports the settings as unsupported is an
        older build whose pipe genuinely runs at the fallback format."""
        if not hasattr(self._player_service, "get_setting"):
            return FALLBACK_TONE_RATE_HZ, FALLBACK_TONE_BITS

        from autostream_players import SETTING_PIPE_SAMPLE_RATE, SETTING_PIPE_BITS_PER_SAMPLE

        def read(key):
            """(value, transient_failure): value None when unsupported."""
            for attempt in range(3):
                result = None
                try:
                    result = self._player_service.get_setting(base_url, key, timeout=3)
                except Exception:
                    _log.debug("AlignRun: pipe format probe error", exc_info=True)
                if result is not None and getattr(result, "unsupported", False):
                    return None, False
                if result is not None and getattr(result, "ok", False):
                    try:
                        return int(result.value), False
                    except (TypeError, ValueError):
                        return None, False
                if attempt < 2:
                    self._sleep(1.0)
            return None, True

        rate_value, failed = read(SETTING_PIPE_SAMPLE_RATE)
        if failed:
            return None
        bits_value, failed = read(SETTING_PIPE_BITS_PER_SAMPLE)
        if failed:
            return None
        rate = rate_value if (rate_value or 0) > 0 else FALLBACK_TONE_RATE_HZ
        bits = bits_value if bits_value in (16, 32) else FALLBACK_TONE_BITS
        return rate, bits

    def _compute_guard_seconds(self, base_url: str) -> float:
        """Muted settle time at each window switch: the tone stream reaches
        the receivers a pipe-lead plus a start-buffer after the freq file
        changes, so the previous window's tone must drain while everything
        is muted or the next output audibly plays it."""
        pipe_lead_s = 0.7
        try:
            from autostream_align_tone import PIPE_BUFFER_BYTES
            pipe_lead_s = PIPE_BUFFER_BYTES / float(
                self._tone_rate * TONE_CHANNELS * (self._tone_bits // 8)
            )
        except Exception:
            _log.debug("AlignRun: pipe lead computation failed", exc_info=True)
        start_buffer_s = 2.25
        try:
            from autostream_players import SETTING_START_BUFFER_MS
            result = self._player_service.get_setting(base_url, SETTING_START_BUFFER_MS, timeout=3)
            if getattr(result, "ok", False) and int(result.value) > 0:
                start_buffer_s = int(result.value) / 1000.0
        except Exception:
            _log.debug("AlignRun: start buffer probe failed", exc_info=True)
        return pipe_lead_s + start_buffer_s + 0.5

    def _build_launch_url(self, participants: list, ret_url: str) -> str:
        outs_param = ",".join(
            f"{quote(s.id, safe='')}~{s.freq_hz}~{quote(s.name, safe='')}"
            for s in participants
        )
        return (
            f"{LAUNCH_HOST}#v=1"
            f"&ret={quote(ret_url, safe='')}"
            f"&p={self._period_ms}&k={self._cycles_per_output}&outs={outs_param}"
        )

    # -- cycle thread -----------------------------------------------------------

    def _run_cycle(self) -> None:
        try:
            while not self._stop_event.is_set():
                for i, s in enumerate(self._participants):
                    if self._stop_event.is_set():
                        return
                    with self._lock:
                        self._current_index = i
                    # Stream content lags the freq-file write by the pipe
                    # lead plus the receiver's start buffer, while volume
                    # changes act immediately -- raising the next output
                    # right away makes it audibly play the PREVIOUS
                    # output's queued tone. Switch the frequency first and
                    # hold everything muted for the stream latency, so each
                    # window opens onto its own tone.
                    self._write_freq(s.freq_hz)
                    if not self._hold(self._guard_seconds):
                        return
                    self._set_volume(self._base_url, s.id, self._volume_percent)

                    if self._elapsed() > self._max_seconds:
                        self._timeout()
                        return

                    held = self._hold(self._hold_seconds)
                    self._set_volume(self._base_url, s.id, 0)

                    if not held:
                        return  # stop() / abort() requested mid-hold

                    if self._elapsed() > self._max_seconds:
                        self._timeout()
                        return
                with self._lock:
                    self._cycle_count += 1
        except Exception:
            _log.exception("AlignRun: cycle failed")
            with self._lock:
                self._last_error = "Calibration cycle failed"
            self._stop_event.set()
            self.cleanup()
            with self._lock:
                self._state = "error"

    def _elapsed(self) -> float:
        return self._clock() - self._started_at

    def _hold(self, seconds: float) -> bool:
        """Wait up to *seconds*, polling for a stop request. Returns False if
        stopped early, True if the hold completed."""
        deadline = self._clock() + seconds
        while True:
            if self._stop_event.is_set():
                return False
            remaining = deadline - self._clock()
            if remaining <= 0:
                return True
            self._sleep(min(remaining, self._poll_interval_s))

    def _timeout(self) -> None:
        with self._lock:
            self._last_error = "Calibration timed out"
        self._stop_event.set()
        self.cleanup()
        with self._lock:
            self._state = "idle"

    # -- helper process control --------------------------------------------------

    def _launch_helper(self) -> None:
        # Direct child of this process, running as the same unprivileged
        # user: the FIFO and freq file both live in the service's runtime
        # directory, and systemd-run/system units are root-only from this
        # account. sys.executable keeps the service's own interpreter (the
        # appliance runs from a venv). Cleanup terminates the child; the
        # helper also self-exits after --max-seconds as a backstop.
        cmd = [
            sys.executable,
            TONE_HELPER,
            "--fifo", self._helper_fifo_path(),
            "--rate", str(self._tone_rate),
            "--bits", str(self._tone_bits),
            "--channels", str(TONE_CHANNELS),
            "--period-ms", str(self._period_ms),
            "--burst-ms", str(BURST_MS),
            "--freq-file", self._freq_file,
            "--max-seconds", str(self._max_seconds),
        ]
        self._helper_proc = self._launch(cmd)

    def _helper_fifo_path(self) -> str:
        # Same FIFO the normal audio path feeds into -- calibration owns it
        # exclusively for the duration of the run (start() already refuses
        # to begin while an input is actively streaming).
        try:
            from autostream_config import FIFO_PATH
            return FIFO_PATH
        except Exception:
            return "/run/autostream-pipes/autostream.fifo"

    def _stop_helper(self) -> None:
        proc = self._helper_proc
        self._helper_proc = None
        if proc is None:
            return
        try:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except Exception:
                proc.kill()
        except Exception:
            _log.debug("AlignRun: stop helper failed", exc_info=True)

    def _write_freq(self, freq_hz: int) -> None:
        d = os.path.dirname(self._freq_file)
        if d:
            os.makedirs(d, exist_ok=True)
        tmp = f"{self._freq_file}.tmp"
        with open(tmp, "w") as f:
            f.write(str(int(freq_hz)))
        os.replace(tmp, self._freq_file)

    def _set_volume(self, base_url: str, output_id: str, volume_percent: int) -> None:
        try:
            self._player_service.set_output_volume(base_url, output_id, int(volume_percent), timeout=3)
        except Exception:
            _log.debug("AlignRun: set_output_volume(%s) failed", output_id, exc_info=True)

    def _set_enabled(self, base_url: str, output_id: str, enabled: bool) -> None:
        try:
            self._player_service.set_output_enabled(base_url, output_id, enabled, timeout=3)
        except Exception:
            _log.debug("AlignRun: set_output_enabled(%s) failed", output_id, exc_info=True)

    # -- stop / finish / cleanup --------------------------------------------------

    def abort(self) -> None:
        """User-requested cancel: stop the cycle, discard any pending result."""
        with self._lock:
            if self._state not in ("running", "finishing"):
                return
            self._state = "finishing"
        self._stop_and_join()
        self.cleanup()
        with self._lock:
            self._pending_result = None
            self._last_error = ""
            self._state = "idle"

    def finish(self, result: Optional[AlignResult] = None) -> None:
        """Called when /align/result lands: stop the cycle, restore state,
        and keep *result* as the pending review-page data. Safe to call even
        if the run already stopped on its own (timeout/error)."""
        with self._lock:
            if self._state == "running":
                self._state = "finishing"
        self._stop_and_join()
        self.cleanup()
        with self._lock:
            self._pending_result = result
            self._last_error = ""
            self._state = "idle"

    def _stop_and_join(self) -> None:
        self._stop_event.set()
        thread = self._thread
        if thread is not None and thread.is_alive():
            thread.join(timeout=5)

    def cleanup(self) -> None:
        """Idempotent: stop the helper process, drop the freq file, restore
        exactly what this run touched -- volume for every muted output, and
        selection for every output the run enabled. Never deselects
        anything the run did not itself enable. Always safe to call more
        than once (e.g. once from the cycle thread on error, once from
        finish())."""
        self._stop_helper()
        try:
            if os.path.exists(self._freq_file):
                os.remove(self._freq_file)
        except Exception:
            _log.debug("AlignRun: freq file cleanup failed", exc_info=True)
        with self._lock:
            snapshots = list(self._snapshots)
            base_url = self._base_url
            touched_ids = list(self._touched_ids)
            enabled_ids = list(self._enabled_ids)
        by_id = {s.id: s for s in snapshots}
        for oid in touched_ids:
            s = by_id.get(oid)
            if s is not None:
                self._set_volume(base_url, oid, s.volume_percent)
        for oid in enabled_ids:
            self._set_enabled(base_url, oid, False)

    # -- read-only accessors ----------------------------------------------------

    def status(self) -> dict:
        with self._lock:
            state = self._state
            idx = self._current_index
            participants = list(self._participants)
            cycle_count = self._cycle_count
            started = self._started_at
            last_error = self._last_error
            launch_url = self._launch_url
            has_pending = self._pending_result is not None

        current = participants[idx] if participants and 0 <= idx < len(participants) else None
        seconds_remaining = None
        if state == "running" and started:
            seconds_remaining = max(0, int(self._max_seconds - (self._clock() - started)))

        return {
            "state": state,
            "current_output_id": current.id if current else None,
            "current_output_name": current.name if current else None,
            "cycle_count": cycle_count,
            "seconds_remaining": seconds_remaining,
            "launch_url": launch_url if state == "running" else "",
            "last_error": last_error,
            "has_pending_result": has_pending,
        }

    def snapshots(self) -> list:
        with self._lock:
            return list(self._snapshots)

    def pending_result(self) -> Optional[AlignResult]:
        with self._lock:
            return self._pending_result

    def discard_result(self) -> None:
        with self._lock:
            self._pending_result = None
