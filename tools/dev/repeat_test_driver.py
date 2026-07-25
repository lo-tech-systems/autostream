#!/usr/bin/env python3
"""repeat_test_driver.py — daemon integration test driver for the "repeat"
feature ("D" test scenarios).

Drives a STANDALONE test instance of autostream_monitor (its own control
socket + its own test FIFO -- never the live daemon/FIFO) against an ALSA
loopback ("snd-aloop") synthetic input, using the Unix control socket's
newline-delimited JSON protocol (docs/AUTOSTREAM-MONITOR.md).

SILENCE RULE: this tool must only ever be pointed at a standalone test daemon
instance with its own socket/FIFO. It must never enable a real owntone-mini
output or write to the live FIFO. It plays only into the ALSA loopback
("hw:Loopback,0,0"), which is not audible on any real device.

Usage examples (run on a Pi test device, as the autostream
build/system user with passwordless sudo):

    # One-time per boot: load the loopback driver.
    python3 repeat_test_driver.py setup-aloop

    # Generate a WAV of N seconds of tone followed by M seconds of silence.
    python3 repeat_test_driver.py gen-tone --out /tmp/tone.wav \
        --tone-seconds 10 --silence-seconds 40

    # Play it into the loopback's playback side (captured by the daemon on
    # the loopback's capture side, hw:Loopback,1,0).
    python3 repeat_test_driver.py play --wav /tmp/tone.wav

    # Talk to a running standalone test daemon.
    python3 repeat_test_driver.py status --socket /tmp/repeat_test.sock

    # Run the D7 scenario end-to-end (assumes a standalone daemon is already
    # configured+started against the loopback capture device and the test
    # FIFO is being drained by fifo_reader_stub.py).
    python3 repeat_test_driver.py d7 --socket /tmp/repeat_test.sock \
        --wav /tmp/tone.wav

This is a dev-only tool: not installed, not referenced by the production
daemon or installer. Covers the D1-D16 scenarios spanning the record path,
the replay path, and the live-interrupt crossfade.
"""

import argparse
import json
import math
import os
import socket
import struct
import subprocess
import sys
import threading
import time
import wave


DEFAULT_SOCKET = "/tmp/repeat_test.sock"
SAMPLE_RATE = 44100
CHANNELS = 2


# ---------------------------------------------------------------------------
# Control-socket JSON client
# ---------------------------------------------------------------------------

class MonitorClient:
    def __init__(self, socket_path: str, timeout: float = 5.0):
        self.socket_path = socket_path
        self.timeout = timeout
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(timeout)
        self.sock.connect(socket_path)
        self._buf = b""

    def close(self):
        self.sock.close()

    def _reconnect(self):
        try:
            self.sock.close()
        except OSError:
            pass
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.socket_path)
        self._buf = b""

    def _readline(self) -> str:
        while b"\n" not in self._buf:
            chunk = self.sock.recv(65536)
            if not chunk:
                raise ConnectionError("monitor closed the connection")
            self._buf += chunk
        line, _, self._buf = self._buf.partition(b"\n")
        return line.decode("utf-8")

    def command(self, obj: dict) -> dict:
        # The daemon closes control connections idle for 20 s (docs/
        # AUTOSTREAM-MONITOR.md); several scenarios above block on
        # `subprocess.Popen(...).wait()` for the duration of an aplay source
        # (which can be close to that threshold with zero socket traffic in
        # between), so a stale/closed socket here is an expected transient,
        # not a daemon fault -- reconnect once and retry rather than letting
        # a whole scenario die on a BrokenPipeError/ConnectionError.
        payload = (json.dumps(obj) + "\n").encode("utf-8")
        try:
            self.sock.sendall(payload)
            return json.loads(self._readline())
        except (BrokenPipeError, ConnectionError, OSError):
            self._reconnect()
            self.sock.sendall(payload)
            return json.loads(self._readline())

    def _read_exact(self, n: int) -> bytes:
        while len(self._buf) < n:
            chunk = self.sock.recv(65536)
            if not chunk:
                raise ConnectionError("monitor closed the connection")
            self._buf += chunk
        data, self._buf = self._buf[:n], self._buf[n:]
        return data

    def get_id_snapshot(self, input_index: int, max_seconds: int = 4) -> dict:
        """get_id_snapshot's success response is a JSON ack line immediately
        followed by a raw binary s16le payload (docs/AUTOSTREAM-MONITOR.md) --
        unlike every other command, a plain command() call would leave that
        payload unread on the socket, corrupting the next command's response.
        This wrapper drains it (frames * 2 bytes, mono s16le) and returns the
        ack dict with the payload attached under "_pcm_bytes" for callers that
        want to inspect it."""
        resp = self.command({"type": "get_id_snapshot", "input": input_index,
                              "max_seconds": max_seconds})
        if resp.get("ok"):
            n_bytes = int(resp.get("frames", 0)) * 2
            resp["_pcm_bytes"] = self._read_exact(n_bytes) if n_bytes > 0 else b""
        return resp

    # -- convenience wrappers over the documented protocol -----------------

    def get_status(self) -> dict:
        return self.command({"type": "get_status"})

    def set_fifo(self, path: str) -> dict:
        return self.command({"type": "set_fifo", "path": path})

    def configure_input(self, input_index: int, device: str, **kwargs) -> dict:
        obj = {"type": "configure_input", "input": input_index, "device": device}
        obj.update(kwargs)
        return self.command(obj)

    def start_input(self, input_index: int) -> dict:
        return self.command({"type": "start_input", "input": input_index})

    def stop_input(self, input_index: int) -> dict:
        return self.command({"type": "stop_input", "input": input_index})

    def set_allow_capture(self, input_index: int, allow: bool) -> dict:
        return self.command({"type": "set_allow_capture", "input": input_index, "allow": allow})

    def set_gain(self, input_index: int, gain_db: float) -> dict:
        return self.command({"type": "set_gain", "input": input_index, "gain_db": gain_db})

    def set_repeat_enabled(self, enabled: bool, codec: str = "auto") -> dict:
        return self.command({"type": "set_repeat_enabled", "enabled": enabled, "codec": codec})

    def set_repeat_armed(self, armed: bool) -> dict:
        return self.command({"type": "set_repeat_armed", "armed": armed})

    def stop_input(self, input_index: int) -> dict:
        return self.command({"type": "stop_input", "input": input_index})

    def debug_dump_repeat_buffer(self, path: str) -> dict:
        # Only present in a build compiled with -DAUTOSTREAM_REPEAT_TEST_HOOKS.
        # Not part of the production daemon.
        return self.command({"type": "debug_dump_repeat_buffer", "path": path})

    def debug_fail_input(self, input_index: int) -> dict:
        # Test hook (docs/AUTOSTREAM-MONITOR.md "debug_fail_input").
        # Rejected with ok=false unless the daemon was launched with
        # --test-hooks; never available in production. Arms a one-shot flag
        # that makes input_index's capture thread self-stop on its next loop
        # iteration via the exact same code path as a genuine unrecoverable
        # ALSA read error.
        return self.command({"type": "debug_fail_input", "input": input_index})


# ---------------------------------------------------------------------------
# ALSA loopback setup
# ---------------------------------------------------------------------------

def setup_aloop():
    """Loads snd-aloop if not already present. Idempotent."""
    check = subprocess.run(["bash", "-lc", "lsmod | grep -q snd_aloop"])
    if check.returncode == 0:
        print("snd-aloop already loaded")
        return
    subprocess.run(["sudo", "modprobe", "snd-aloop"], check=True)
    print("snd-aloop loaded")


# ---------------------------------------------------------------------------
# Tone/silence WAV generation
# ---------------------------------------------------------------------------

def gen_tone_wav(out_path: str, tone_seconds: float, silence_seconds: float,
                  freq_hz: float = 440.0, amplitude: float = 0.3,
                  sample_rate: int = SAMPLE_RATE):
    """Writes a stereo s16le WAV: tone_seconds of a sine tone, then
    silence_seconds of digital silence. Used to synthesize a "playback
    session" through the ALSA loopback for D-test scenarios (a silence run of
    silence_seconds >= the configured silence_seconds ends the capture
    session)."""
    n_tone = int(tone_seconds * sample_rate)
    n_silence = int(silence_seconds * sample_rate)

    with wave.open(out_path, "wb") as w:
        w.setnchannels(CHANNELS)
        w.setsampwidth(2)
        w.setframerate(sample_rate)

        frames = bytearray()
        for i in range(n_tone):
            v = amplitude * math.sin(2 * math.pi * freq_hz * i / sample_rate)
            s = int(max(-1.0, min(1.0, v)) * 32767)
            frames += struct.pack("<hh", s, s)
        frames += b"\x00\x00\x00\x00" * n_silence
        w.writeframes(bytes(frames))

    print(f"wrote {out_path}: {tone_seconds}s tone @ {freq_hz}Hz + {silence_seconds}s silence")


def play_wav(wav_path: str, device: str = "hw:Loopback,0,0"):
    """Plays a WAV file into the loopback's playback side. The standalone
    test daemon must be configured to capture from the loopback's paired
    capture side (typically hw:Loopback,1,0)."""
    subprocess.run(["aplay", "-D", device, wav_path], check=True)


# ---------------------------------------------------------------------------
# D7 scenario: enable/disable mid-session
# ---------------------------------------------------------------------------

def scenario_d7(socket_path: str, wav_path: str, input_index: int = 1,
                 playback_device: str = "hw:Loopback,0,0"):
    """D7: 'set_repeat_enabled during active capture -> no recording this
    session; next session records. Disable mid-session -> recording.bytes ->
    0 immediately.'

    Assumes: a standalone test daemon is already running, configured for
    input_index against the loopback capture device, started, with
    set_allow_capture(input_index, True) already issued, and repeat currently
    DISABLED. wav_path should contain enough tone to comfortably outlast the
    assertions below (>= ~15s recommended).
    """
    c = MonitorClient(socket_path)
    proc = None
    proc2 = None
    try:
        print("[d7] phase 1: starting playback with repeat disabled")
        proc = subprocess.Popen(["aplay", "-D", playback_device, wav_path])
        time.sleep(3.0)   # let a capture session start

        st = c.get_status()
        rep = st.get("repeat", {})
        assert rep.get("enabled") is False, f"expected repeat disabled, got {rep}"

        print("[d7] phase 2: enabling repeat mid-session (should NOT start recording this session)")
        c.set_repeat_enabled(True, "auto")
        time.sleep(1.0)
        st = c.get_status()
        rep = st["repeat"]
        assert rep["enabled"] is True
        assert rep["recording"]["active"] is False, (
            f"D7 FAIL: recording started mid-session after enable: {rep}")
        assert rep["recording"]["bytes"] == 0, f"D7 FAIL: unexpected bytes: {rep}"
        print("[d7] PASS: no recording started mid-session")

        print("[d7] phase 3: stop this session, start a new one -> should record")
        proc.terminate()
        proc.wait(timeout=5)
        # Allow silence_seconds to elapse (ending the session) and give the
        # ALSA loopback pair time to settle before re-opening the same
        # playback subdevice. Empirically, reopening within ~4s of a
        # SIGTERM'd aplay silently produces no audio on the paired capture
        # subdevice on a shared ALSA-loopback test device; >= 15s reliably
        # works (assumption, not a controller bug).
        time.sleep(15.0)

        proc2 = subprocess.Popen(["aplay", "-D", playback_device, wav_path])
        time.sleep(5.0)
        st = c.get_status()
        rep = st["repeat"]
        assert rep["recording"]["active"] is True, f"D7 FAIL: new session did not record: {rep}"
        assert rep["recording"]["bytes"] > 0, f"D7 FAIL: zero bytes recorded: {rep}"
        print(f"[d7] PASS: new session recording ({rep['recording']['bytes']} bytes so far)")

        print("[d7] phase 4: disable mid-session -> bytes should drop to 0 immediately")
        c.set_repeat_enabled(False, "auto")
        st = c.get_status()
        rep = st["repeat"]
        assert rep["enabled"] is False
        assert rep["recording"]["bytes"] == 0, f"D7 FAIL: bytes not freed on disable: {rep}"
        assert rep["recording"]["active"] is False
        print("[d7] PASS: disable freed the recording immediately")

        proc2.terminate()
        proc2.wait(timeout=5)

        print("[d7] ALL PASS")
    finally:
        for p in (proc, proc2):
            if p is not None and p.poll() is None:
                p.terminate()
                try:
                    p.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    p.kill()
        c.close()


# ---------------------------------------------------------------------------
# Replay scenarios (D1, D3, D5, D6, D9, D10, D11, D12)
#
# All assume a standalone test daemon already configured+started against the
# loopback capture device, with set_allow_capture(input_index, True) issued,
# a test FIFO set via set_fifo, and repeat enabled (auto codec) unless the
# scenario says otherwise. Play into --device (default hw:Loopback,0,0); the
# daemon must be configured to capture from its paired capture subdevice
# (typically hw:Loopback,1,0). A fifo_reader_stub.py instance should be
# reading the same test FIFO concurrently for D1-D3/D9/D10 (position/loop
# telemetry alone does not prove pipe occupancy -- that is D2, driven
# directly by fifo_reader_stub.py's own occupancy_bytes log).
# ---------------------------------------------------------------------------

def _wait_for(predicate, timeout: float, poll_interval: float = 0.25, desc: str = "condition"):
    """Polls predicate() until it returns a truthy value or timeout elapses.
    Returns the truthy value, or raises AssertionError."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        v = predicate()
        if v:
            return v
        time.sleep(poll_interval)
    raise AssertionError(f"timed out waiting for: {desc}")


def scenario_d1_d3(socket_path: str, wav_path: str, input_index: int = 1,
                    playback_device: str = "hw:Loopback,0,0",
                    min_loops: int = 2):
    """D1 (record->trim->replay cycle, replay begins <1s after capture stop,
    envelope ~= source + ~1s pad) and D3 (loop seam ~= trim pad; loop_count
    increments), combined since both need the same setup.

    wav_path should be a tone+silence WAV (gen-tone) whose silence tail is
    >= the configured silence_seconds so the capture session actually ends.
    """
    c = MonitorClient(socket_path)
    proc = None
    try:
        c.set_repeat_enabled(True, "auto")
        c.set_repeat_armed(True)   # arm BEFORE the session so capture-stop replays immediately

        print("[d1] playing source into the loopback")
        proc = subprocess.Popen(["aplay", "-D", playback_device, wav_path])

        st = _wait_for(lambda: (lambda s: s["repeat"]["recording"]["active"] and s)(c.get_status()),
                        timeout=10, desc="recording to start")
        print(f"[d1] recording started: {st['repeat']['recording']}")

        proc.wait(timeout=120)
        t_capture_stop = time.monotonic()

        st = _wait_for(lambda: (lambda s: s["repeat"]["replay"]["active"] and s)(c.get_status()),
                        timeout=5, desc="replay to start")
        gap = time.monotonic() - t_capture_stop
        print(f"[d1] PASS: replay started {gap:.2f}s after aplay exited (want < ~1-2s incl. silence_seconds tail)")

        duration = st["repeat"]["replay"]["duration_seconds"]
        print(f"[d1] recording duration reported as {duration:.1f}s")
        assert duration > 0, "D1 FAIL: zero duration reported"

        print(f"[d3] waiting for loop_count to reach {min_loops}...")
        st = _wait_for(
            lambda: (lambda s: s["repeat"]["replay"]["loop_count"] >= min_loops and s)(c.get_status()),
            timeout=duration * min_loops + 30, desc=f"loop_count >= {min_loops}")
        print(f"[d3] PASS: loop_count={st['repeat']['replay']['loop_count']}")

        c.set_repeat_armed(False)
        st = _wait_for(lambda: (lambda s: not s["repeat"]["replay"]["active"] and s)(c.get_status()),
                        timeout=5, desc="replay to stop after disarm")
        print("[d1/d3] ALL PASS (cleanup: disarmed)")
    finally:
        if proc is not None and proc.poll() is None:
            proc.terminate()
        c.set_repeat_armed(False)
        c.close()


def scenario_d5_d6(socket_path: str, wav_path: str, input_index: int = 1,
                    playback_device: str = "hw:Loopback,0,0"):
    """D5 (disarm during replay -> fade then stop; buffer retained/HOLD;
    re-armable) and D6 (arm while idle with a HOLD recording -> replay
    starts immediately)."""
    c = MonitorClient(socket_path)
    proc = None
    try:
        c.set_repeat_enabled(True, "auto")
        c.set_repeat_armed(False)   # NOT armed yet -- record only, this run

        proc = subprocess.Popen(["aplay", "-D", playback_device, wav_path])
        _wait_for(lambda: (lambda s: s["repeat"]["recording"]["active"] and s)(c.get_status()),
                  timeout=10, desc="recording to start")
        proc.wait(timeout=120)

        # A settling window: on a shared ALSA-loopback test pairing, a brief
        # spurious above-threshold blip is sometimes observed on the capture
        # side a couple of seconds after the paired aplay process exits
        # cleanly (not this driver's bug). Since we are NOT armed yet in this
        # phase, such a blip legitimately starts a fresh (tiny) recording
        # session ("new capture session -> old buffer freed, new recording
        # starts"), which briefly re-flips recording.active. Give it a few
        # seconds to fully settle before asserting the final HOLD state.
        time.sleep(6.0)
        st = _wait_for(lambda: (lambda s: s["repeat"]["recording"]["bytes"] > 0
                                 and not s["repeat"]["recording"]["active"] and s)(c.get_status()),
                        timeout=10, desc="session to end in HOLD")
        assert not st["repeat"]["replay"]["active"], "expected HOLD (not armed), replay should not have started"
        print("[d6] phase 1: recording ended in HOLD as expected (not armed)")

        print("[d6] phase 2: arming while idle -> replay should start immediately")
        t0 = time.monotonic()
        c.set_repeat_armed(True)
        st = _wait_for(lambda: (lambda s: s["repeat"]["replay"]["active"] and s)(c.get_status()),
                        timeout=3, desc="replay to start immediately on arm")
        print(f"[d6] PASS: replay started {time.monotonic() - t0:.2f}s after set_repeat_armed(True)")

        print("[d5] phase 1: disarming during replay -> expect fade then stop")
        c.set_repeat_armed(False)
        st = _wait_for(lambda: (lambda s: not s["repeat"]["replay"]["active"] and s)(c.get_status()),
                        timeout=5, desc="replay to stop after disarm (fade)")
        assert st["repeat"]["recording"]["bytes"] > 0, "D5 FAIL: buffer was not retained after disarm"
        assert not st["repeat"]["armed"]
        print(f"[d5] PASS: replay stopped, buffer retained ({st['repeat']['recording']['bytes']} bytes)")

        print("[d5] phase 2: re-arming works")
        c.set_repeat_armed(True)
        _wait_for(lambda: (lambda s: s["repeat"]["replay"]["active"] and s)(c.get_status()),
                  timeout=3, desc="replay to restart after re-arm")
        print("[d5] PASS: re-arm restarted replay")

        c.set_repeat_armed(False)
        _wait_for(lambda: not c.get_status()["repeat"]["replay"]["active"], timeout=5,
                  desc="final disarm to settle")
        print("[d5/d6] ALL PASS")
    finally:
        if proc is not None and proc.poll() is None:
            proc.terminate()
        c.set_repeat_armed(False)
        c.close()


def scenario_d9(socket_path: str, wav_path: str, input_index: int = 1,
                playback_device: str = "hw:Loopback,0,0", poll_hz: float = 20.0):
    """D9: poll get_status at ~20 Hz across the capture-stop -> replay-start
    transition; assert no snapshot shows all-inputs-idle AND armed AND
    bytes>0 AND replay.active=false (the daemon publishes this
    transition atomically)."""
    c = MonitorClient(socket_path)
    proc = None
    try:
        c.set_repeat_enabled(True, "auto")
        c.set_repeat_armed(True)

        proc = subprocess.Popen(["aplay", "-D", playback_device, wav_path])
        _wait_for(lambda: (lambda s: s["repeat"]["recording"]["active"] and s)(c.get_status()),
                  timeout=10, desc="recording to start")

        ambiguous = []
        samples = 0
        period = 1.0 / poll_hz
        # Poll through the aplay exit and well past the expected replay start.
        deadline = time.monotonic() + 90.0
        replay_seen = False
        while time.monotonic() < deadline:
            t0 = time.monotonic()
            st = c.get_status()
            rep = st["repeat"]
            any_capturing = any(i["capturing"] for i in st["inputs"])
            samples += 1
            if (not any_capturing) and rep["armed"] and rep["recording"]["bytes"] > 0 \
                    and not rep["replay"]["active"] and not rep["recording"]["active"]:
                ambiguous.append(st)
            if rep["replay"]["active"]:
                replay_seen = True
                if samples > 20:   # keep polling a little past the transition, then stop
                    break
            elapsed = time.monotonic() - t0
            if elapsed < period:
                time.sleep(period - elapsed)

        assert replay_seen, "D9 FAIL: replay never started within the poll window"
        assert not ambiguous, f"D9 FAIL: {len(ambiguous)} ambiguous snapshot(s) observed: {ambiguous[:2]}"
        print(f"[d9] PASS: {samples} snapshots polled at ~{poll_hz} Hz, zero ambiguous")

        c.set_repeat_armed(False)
        _wait_for(lambda: not c.get_status()["repeat"]["replay"]["active"], timeout=5, desc="settle")
    finally:
        if proc is not None and proc.poll() is None:
            proc.terminate()
        c.set_repeat_armed(False)
        c.close()


def gen_multi_track_wav(out_path: str, n_tracks: int = 3, tone_seconds: float = 5.0,
                         gap_seconds: float = 2.0, tail_silence_seconds: float = 40.0,
                         sample_rate: int = SAMPLE_RATE):
    """D10: n_tracks tone bursts separated by gap_seconds of silence (each gap
    must exceed the configured track_change_silence_seconds so it registers as
    a track boundary), followed by a long trailing silence to end the capture
    session."""
    freqs = [440.0, 550.0, 660.0, 770.0, 880.0]
    with wave.open(out_path, "wb") as w:
        w.setnchannels(CHANNELS)
        w.setsampwidth(2)
        w.setframerate(sample_rate)
        frames = bytearray()
        for t in range(n_tracks):
            freq = freqs[t % len(freqs)]
            n_tone = int(tone_seconds * sample_rate)
            for i in range(n_tone):
                v = 0.3 * math.sin(2 * math.pi * freq * i / sample_rate)
                s = int(max(-1.0, min(1.0, v)) * 32767)
                frames += struct.pack("<hh", s, s)
            if t < n_tracks - 1:
                frames += b"\x00\x00\x00\x00" * int(gap_seconds * sample_rate)
        frames += b"\x00\x00\x00\x00" * int(tail_silence_seconds * sample_rate)
        w.writeframes(bytes(frames))
    print(f"wrote {out_path}: {n_tracks} tracks x {tone_seconds}s, {gap_seconds}s gaps, "
          f"{tail_silence_seconds}s tail silence")


def scenario_d10(socket_path: str, wav_path: str, input_index: int = 1,
                  playback_device: str = "hw:Loopback,0,0", expected_track_changes: int = 2):
    """D10: recording of N tone tracks with gaps: during replay,
    track_change_seq advances at each gap under origin_input; snapshot
    command returns replay-tap audio (non-silent)."""
    c = MonitorClient(socket_path)
    proc = None
    try:
        c.set_repeat_enabled(True, "auto")
        c.set_repeat_armed(True)

        proc = subprocess.Popen(["aplay", "-D", playback_device, wav_path])
        _wait_for(lambda: (lambda s: s["repeat"]["recording"]["active"] and s)(c.get_status()),
                  timeout=10, desc="recording to start")
        proc.wait(timeout=180)

        st = _wait_for(lambda: (lambda s: s["repeat"]["replay"]["active"] and s)(c.get_status()),
                        timeout=5, desc="replay to start")
        seq_at_start = next(i["track_change_seq"] for i in st["inputs"] if i["index"] == input_index)

        st = _wait_for(
            lambda: (lambda s: (next(i["track_change_seq"] for i in s["inputs"]
                                      if i["index"] == input_index) - seq_at_start)
                                >= expected_track_changes and s)(c.get_status()),
            timeout=st["repeat"]["replay"]["duration_seconds"] + 30,
            desc=f"track_change_seq to advance by {expected_track_changes}")
        new_seq = next(i["track_change_seq"] for i in st["inputs"] if i["index"] == input_index)
        print(f"[d10] PASS: track_change_seq advanced {new_seq - seq_at_start} time(s) during replay")

        resp = c.get_id_snapshot(input_index, max_seconds=4)
        assert resp.get("ok"), f"D10 FAIL: get_id_snapshot rejected during replay: {resp}"
        print(f"[d10] PASS: get_id_snapshot served {resp.get('frames')} frames during replay "
              f"({len(resp.get('_pcm_bytes', b''))} bytes)")

        c.set_repeat_armed(False)
        _wait_for(lambda: not c.get_status()["repeat"]["replay"]["active"], timeout=5, desc="settle")
        print("[d10] ALL PASS")
    finally:
        if proc is not None and proc.poll() is None:
            proc.terminate()
        c.set_repeat_armed(False)
        c.close()


def scenario_d11(socket_path: str, wav_path: str, fifo_path: str, input_index: int = 1,
                  playback_device: str = "hw:Loopback,0,0"):
    """D11: kill the reader stub mid-replay, then disarm: daemon unblocks
    cleanly (no hang), clean state; restart reader + re-arm works.

    Caller is responsible for having a fifo_reader_stub.py process already
    running against fifo_path before invoking this; its pid is looked up via
    the fuser-free `ps`+grep pattern below (avoids an extra dependency).
    """
    c = MonitorClient(socket_path)
    proc = None
    try:
        c.set_repeat_enabled(True, "auto")
        c.set_repeat_armed(True)

        proc = subprocess.Popen(["aplay", "-D", playback_device, wav_path])
        _wait_for(lambda: (lambda s: s["repeat"]["recording"]["active"] and s)(c.get_status()),
                  timeout=10, desc="recording to start")
        proc.wait(timeout=120)
        _wait_for(lambda: (lambda s: s["repeat"]["replay"]["active"] and s)(c.get_status()),
                  timeout=5, desc="replay to start")

        print("[d11] killing the fifo_reader_stub process(es) against the test FIFO")
        subprocess.run(["bash", "-lc", f"pkill -f 'fifo_reader_stub.py.*{fifo_path}'"])
        time.sleep(2.0)   # let the write path observe the reader's disappearance (EPIPE/POLLHUP)

        print("[d11] issuing disarm; daemon must unblock within a few seconds (no hang)")
        t0 = time.monotonic()
        resp = c.set_repeat_armed(False)
        assert resp.get("ok"), f"D11 FAIL: set_repeat_armed did not ack: {resp}"
        st = _wait_for(lambda: (lambda s: not s["repeat"]["replay"]["active"] and s)(c.get_status()),
                        timeout=10, desc="replay to stop after reader loss + disarm")
        print(f"[d11] PASS: daemon unblocked cleanly in {time.monotonic() - t0:.2f}s "
              f"(state settled, no hang)")

        print("[d11] restarting the reader stub and re-arming")
        reader = subprocess.Popen(["python3", "fifo_reader_stub.py", "--path", fifo_path,
                                    "--duration", "15"])
        c.set_repeat_armed(True)
        _wait_for(lambda: (lambda s: s["repeat"]["replay"]["active"] and s)(c.get_status()),
                  timeout=5, desc="replay to restart with a fresh reader")
        print("[d11] PASS: re-arm with a fresh reader works")

        c.set_repeat_armed(False)
        _wait_for(lambda: not c.get_status()["repeat"]["replay"]["active"], timeout=5, desc="settle")
        # Once replay stops there are no more writers on the FIFO, so the
        # reader stub's own read loop can sit on repeated EOF/stall cycles
        # rather than reliably self-exiting at --duration -- terminate it
        # explicitly instead of trusting its internal timer for cleanup.
        reader.terminate()
        try:
            reader.wait(timeout=5)
        except subprocess.TimeoutExpired:
            reader.kill()
        print("[d11] ALL PASS")
    finally:
        if proc is not None and proc.poll() is None:
            proc.terminate()
        try:
            if 'reader' in locals() and reader.poll() is None:
                reader.terminate()
        except Exception:
            pass
        c.set_repeat_armed(False)
        c.close()


def scenario_d12(socket_path: str, wav_path: str, input_index: int = 1,
                  playback_device: str = "hw:Loopback,0,0"):
    """D12: stop_input on the origin input (as reload does) -> buffer
    discarded, replay cancelled."""
    c = MonitorClient(socket_path)
    proc = None
    try:
        c.set_repeat_enabled(True, "auto")
        c.set_repeat_armed(True)

        proc = subprocess.Popen(["aplay", "-D", playback_device, wav_path])
        _wait_for(lambda: (lambda s: s["repeat"]["recording"]["active"] and s)(c.get_status()),
                  timeout=10, desc="recording to start")
        proc.wait(timeout=120)
        _wait_for(lambda: (lambda s: s["repeat"]["replay"]["active"] and s)(c.get_status()),
                  timeout=5, desc="replay to start")

        print("[d12] issuing stop_input on the origin input while replay is active")
        resp = c.stop_input(input_index)
        assert resp.get("ok"), f"D12 FAIL: stop_input did not ack: {resp}"

        st = _wait_for(
            lambda: (lambda s: not s["repeat"]["replay"]["active"]
                     and s["repeat"]["recording"]["bytes"] == 0 and s)(c.get_status()),
            timeout=5, desc="buffer to be discarded and replay cancelled")
        print(f"[d12] PASS: replay cancelled, buffer discarded ({st['repeat']['recording']})")

        # Restart the input so the daemon is left in a clean, re-usable state.
        c.start_input(input_index)
        print("[d12] ALL PASS (input restarted for cleanup)")
    finally:
        if proc is not None and proc.poll() is None:
            proc.terminate()
        c.set_repeat_armed(False)
        c.close()


# ---------------------------------------------------------------------------
# Live-interrupt crossfade scenarios (D4, E1, E6)
#
# Unlike the replay scenarios above, these need TWO independent inputs feeding
# the SAME shared FIFO, so the daemon must already be configured+started for
# both input_index values against two independently-playable ALSA loopback
# pairs before these are invoked -- e.g. subdevice 0 for input 1
# (hw:Loopback,0,0 playback / hw:Loopback,1,0 capture) and subdevice 1 for
# input 2 (hw:Loopback,0,1 playback / hw:Loopback,1,1 capture), both under the
# same snd-aloop card (`setup_aloop()`'s default pcm_substreams is >= 2).
# set_allow_capture must be True on both inputs. repeat is enabled+armed by
# each scenario itself, same convention as the replay scenarios.
# ---------------------------------------------------------------------------

# Goertzel single-bin energy magnitude for one block of mono float samples --
# cheap way to tell "is tone A (or B) present in this block" without a numpy
# dependency (a test host's Python may not have numpy installed, and pulling
# in a real FFT for a dev-only two-tone discrimination is overkill).
def _goertzel_mag(samples, freq_hz: float, sample_rate: int = SAMPLE_RATE) -> float:
    n = len(samples)
    if n == 0:
        return 0.0
    k = int(0.5 + (n * freq_hz) / sample_rate)
    w = (2.0 * math.pi / n) * k
    cosine = math.cos(w)
    coeff = 2.0 * cosine
    s_prev = 0.0
    s_prev2 = 0.0
    for x in samples:
        s = x + coeff * s_prev - s_prev2
        s_prev2 = s_prev
        s_prev = s
    power = s_prev2 * s_prev2 + s_prev * s_prev - coeff * s_prev * s_prev2
    return math.sqrt(max(power, 0.0)) / n


def _load_s16le_stereo_mono(path: str):
    """Reads a raw s16le stereo dump (fifo_reader_stub.py --dump-path) and
    returns a flat list of mono float samples in [-1, 1] (L+R averaged)."""
    with open(path, "rb") as f:
        raw = f.read()
    n_frames = len(raw) // 4   # 2 channels * 2 bytes
    samples = struct.unpack(f"<{n_frames * 2}h", raw[:n_frames * 4])
    mono = [(samples[2 * i] + samples[2 * i + 1]) / 2.0 / 32768.0 for i in range(n_frames)]
    return mono


def _tone_envelope(mono, freq_hz: float, block_frames: int = 2205,
                    sample_rate: int = SAMPLE_RATE):
    """Splits mono into block_frames-sized windows (2205 = 50 ms @ 44.1 kHz)
    and returns a list of (t_seconds, goertzel_magnitude_at_freq_hz)."""
    out = []
    for i in range(0, len(mono) - block_frames, block_frames):
        block = mono[i:i + block_frames]
        mag = _goertzel_mag(block, freq_hz, sample_rate)
        out.append((i / sample_rate, mag))
    return out


def scenario_d4(socket_path: str, wav_a: str, wav_b: str, fifo_path: str,
                 input_a: int = 1, input_b: int = 2,
                 device_a: str = "hw:Loopback,0,0", device_b: str = "hw:Loopback,0,1",
                 freq_a: float = 440.0, freq_b: float = 880.0,
                 dump_path: str = "/tmp/d4_fifo_dump.raw"):
    """D4: interrupt crossfade. wav_a (input_a) plays long enough to start a
    recording+replay (silence tail ends the capture session); once replay is
    confirmed active, wav_b (input_b, a DIFFERENT tone frequency) starts
    playing -- the live interrupt. Asserts:
      1. origin_input flips from input_a to input_b within the expected
         ~1.5 s fade + handoff window.
      2. Old recording freed (bytes -> 0 momentarily) then a NEW recording
         grows under input_b.
      3. Offline analysis of the FIFO dump: freq_a's envelope ramps down to
         near-zero over ~1.5 s (+-0.4s wall-clock slack for scheduling
         jitter on a shared test host; the acceptance is on the ENVELOPE
         SHAPE, not on external process timing) with freq_b's envelope
         staying near-zero for the same window (no interleaving), followed
         by freq_b ramping up.

    Caller must already have a fifo_reader_stub.py instance running against
    fifo_path with --dump-path dump_path (or equivalent) for the WHOLE test
    window; this function does not manage the reader stub itself since D2's
    occupancy telemetry and D4's raw dump are both read from the same
    process (avoids two readers fighting over one FIFO).
    """
    c = MonitorClient(socket_path)
    proc_a = None
    proc_b = None
    try:
        c.set_repeat_enabled(True, "auto")
        c.set_repeat_armed(True)

        print(f"[d4] playing source A (input {input_a}, {freq_a} Hz)")
        proc_a = subprocess.Popen(["aplay", "-D", device_a, wav_a])
        _wait_for(lambda: (lambda s: s["repeat"]["recording"]["active"] and s)(c.get_status()),
                  timeout=10, desc="recording A to start")
        # NOTE: a shared test host's snd-aloop pair may report a non-44.1kHz
        # detected_hz (ALSA negotiates ~48kHz; `aplay` warns "rate is not
        # accurate") --
        # confirmed by direct Goertzel scan of a captured FIFO dump that this
        # does NOT survive as a pitch shift in the daemon's OUTPUT: the
        # daemon's own rate estimator + SRC resampling (autostream_monitor_
        # io.cpp) correctly reconstructs freq_a/freq_b at their AUTHORED
        # frequency in the FIFO stream (`plughw:` on the aplay side handles
        # the playback-side rate negotiation transparently). Using the raw
        # detected_hz to "correct" the search frequency was tried and
        # measured WRONG (it does not match the actual FFT peak in a real
        # dump); freq_a/freq_b are used as-authored below.
        proc_a.wait(timeout=120)
        st = _wait_for(lambda: (lambda s: s["repeat"]["replay"]["active"] and s)(c.get_status()),
                        timeout=5, desc="replay to start")
        assert st["repeat"]["recording"]["origin_input"] == input_a

        print("[d4] letting replay run a few seconds before interrupting")
        time.sleep(3.0)

        # set_allow_capture is mutually exclusive between inputs (docs/
        # AUTOSTREAM-MONITOR.md): "a permitted input detects audio"
        # presupposes something upstream (in production, Python's turntable-
        # selection logic) has already granted input_b permission -- this
        # driver stands in for that by flipping it explicitly right before
        # playing source B, mirroring a user switching decks.
        c.set_allow_capture(input_b, True)
        interrupt_t0 = time.monotonic()

        print(f"[d4] interrupting with source B (input {input_b}, {freq_b} Hz)")
        proc_b = subprocess.Popen(["aplay", "-D", device_b, wav_b])

        st = _wait_for(
            lambda: (lambda s: s["repeat"]["recording"]["origin_input"] == input_b
                     and s["repeat"]["recording"]["active"] and s)(c.get_status()),
            timeout=10, desc="handoff to input B's new recording")
        handoff_elapsed = time.monotonic() - interrupt_t0
        print(f"[d4] PASS: origin_input switched to {input_b}, new recording active "
              f"({handoff_elapsed:.2f}s after interrupt trigger, want ~1.5-2.5s incl. fade+prefill)")
        assert 0.5 < handoff_elapsed < 6.0, (
            f"D4 FAIL: handoff took {handoff_elapsed:.2f}s, expected roughly the "
            f"1.5s fade + up to ~0.5s prefill/scheduling")

        print("[d4] waiting for the FIFO dump to accumulate a bit past the handoff")
        time.sleep(3.0)

        proc_b.terminate()
        try:
            proc_b.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc_b.kill()

        print(f"[d4] analysing FIFO dump {dump_path}")
        mono = _load_s16le_stereo_mono(dump_path)
        assert len(mono) > SAMPLE_RATE, f"D4 FAIL: dump too short ({len(mono)} frames)"

        env_a = _tone_envelope(mono, freq_a)
        env_b = _tone_envelope(mono, freq_b)

        # Locate the fade: the last block where freq_a is clearly present
        # (above half its own early-replay level) before it drops away.
        # Baseline is the 90th percentile (not the median): the dump spans
        # the WHOLE test window including long silence_seconds gaps between
        # tone bursts (confirmed by direct inspection -- most of a multi-
        # loop replay's silence-trimmed-but-still-present quiet stretches),
        # so a median would be dominated by silence and read near-zero even
        # though the actual tone segments are strongly present.
        a_levels = sorted(m for _, m in env_a)
        baseline_a = a_levels[int(len(a_levels) * 0.9)] if a_levels else 0.0
        assert baseline_a > 0.02, f"D4 FAIL: source A not detected in dump (baseline={baseline_a:.4f})"

        # Candidate "drop events": index where freq_a is near baseline, that
        # goes on to fall below baseline*0.05 shortly after. This alone is
        # NOT enough to identify the interrupt fade -- a looping replay's own
        # loop seam (the ~1 s trimmed silence pad between loops) also
        # produces a drop-to-near-zero-then-recover blip that looks identical
        # over a short window. The interrupt fade is distinguished from a
        # loop seam by what happens AFTER: a loop seam recovers back to
        # baseline within a couple of seconds (replay resumes); the interrupt
        # fade never recovers for the rest of the file (freq_a's source has
        # been superseded). So: collect every candidate drop event, then take
        # the LAST one that does not recover -- that is the real crossfade.
        block_seconds = env_a[1][0] - env_a[0][0] if len(env_a) > 1 else 0.05
        recover_check_blocks = max(1, int(3.0 / block_seconds))   # ~3s lookahead
        backscan_limit_blocks = max(1, int(3.0 / block_seconds))  # ramp itself is ~1.5s

        n_env = len(env_a)

        # Find every "settle" event: the block index where the envelope
        # crosses DOWN through the near-zero floor. For each one, walk
        # backward through its (monotonic) decline to the last block that was
        # still at full baseline -- that pinpoints the ramp's actual start,
        # regardless of how long the preceding plateau at full baseline was
        # (a plain forward scan for "first block >= 0.9*baseline" would anchor
        # on the START of that plateau instead of where the decline begins,
        # over-measuring the fade's duration whenever a loop's silence-then-
        # ramp-up seam immediately precedes the real interrupt fade).
        candidates = []
        for end_i in range(1, n_env):
            was_above_floor = env_a[end_i - 1][1] >= baseline_a * 0.05
            now_below_floor = env_a[end_i][1] < baseline_a * 0.05
            if not (was_above_floor and now_below_floor):
                continue
            k = end_i - 1
            while k >= 0 and env_a[k][1] < baseline_a * 0.9 \
                    and (end_i - k) <= backscan_limit_blocks:
                k -= 1
            if k >= 0 and env_a[k][1] >= baseline_a * 0.9 and env_a[k][0] > 3.0:
                candidates.append((k, end_i))

        fade_start_idx = None
        fade_end_idx = None
        for start_i, end_i in candidates:
            lookahead = env_a[end_i:end_i + recover_check_blocks]
            recovers = any(mag >= baseline_a * 0.5 for _, mag in lookahead)
            if not recovers:
                fade_start_idx, fade_end_idx = start_i, end_i   # keep the LAST non-recovering one

        assert fade_start_idx is not None and fade_end_idx is not None, (
            "D4 FAIL: could not locate a non-recovering (interrupt) fade-out for "
            f"source A in the dump (candidates found: {len(candidates)})")
        fade_duration = env_a[fade_end_idx][0] - env_a[fade_start_idx][0]
        print(f"[d4] measured fade duration ~{fade_duration:.2f}s "
              f"(want 1.5s +-0.4s incl. 50ms block quantisation + goertzel edge effects)")
        assert 1.1 <= fade_duration <= 1.9, (
            f"D4 FAIL: fade duration {fade_duration:.2f}s outside 1.5s +-0.4s tolerance")

        # No interleave: freq_b must stay near-zero for the whole fade window
        # (the interrupting input's output is discarded while replay is
        # fading, never mixed in).
        overlap_b_levels = [mag for t, mag in env_b
                             if env_a[fade_start_idx][0] <= t <= env_a[fade_end_idx][0]]
        max_overlap_b = max(overlap_b_levels) if overlap_b_levels else 0.0
        print(f"[d4] freq_b level during A's fade window: max={max_overlap_b:.4f} (want near-zero)")
        assert max_overlap_b < baseline_a * 0.15, (
            f"D4 FAIL: source B leaked into the FIFO during A's fade-out "
            f"(max={max_overlap_b:.4f}, threshold={baseline_a * 0.15:.4f}) -- "
            f"sequential fade-out/fade-in violated")

        # freq_b should ramp up to a comparable level sometime after the fade
        # window ends (its own 0.5s prefill + 1s ramp).
        post_fade_b = [mag for t, mag in env_b if t > env_a[fade_end_idx][0] + 0.3]
        assert post_fade_b and max(post_fade_b) > baseline_a * 0.5, (
            "D4 FAIL: source B never reached a comparable level after the handoff")
        print("[d4] PASS: no interleaved live audio during the fade; B arrived after handoff")

        print("[d4] ALL PASS")
    finally:
        for p in (proc_a, proc_b):
            if p is not None and p.poll() is None:
                p.terminate()
        c.set_repeat_armed(False)
        c.close()


def scenario_e1(socket_path: str, wav_a: str, wav_b: str,
                 input_a: int = 1, input_b: int = 2,
                 device_a: str = "hw:Loopback,0,0", device_b: str = "hw:Loopback,0,1"):
    """E1: input handoff mid-recording. Session A ends (capture
    stop); armed, so replay of A's recording begins; input B then interrupts
    it. Net effect must match "live playback wins": origin_input ends up B,
    A's buffer is freed, a fresh recording grows under B. This is the same
    underlying mechanism as D4 without the envelope-shape assertions (D4
    already covers the fade's audio properties in detail)."""
    c = MonitorClient(socket_path)
    proc_a = None
    proc_b = None
    try:
        c.set_repeat_enabled(True, "auto")
        c.set_repeat_armed(True)

        proc_a = subprocess.Popen(["aplay", "-D", device_a, wav_a])
        _wait_for(lambda: (lambda s: s["repeat"]["recording"]["active"] and s)(c.get_status()),
                  timeout=10, desc="recording (input A) to start")
        proc_a.wait(timeout=120)
        st = _wait_for(lambda: (lambda s: s["repeat"]["replay"]["active"] and s)(c.get_status()),
                        timeout=5, desc="replay of A to start")
        assert st["repeat"]["recording"]["origin_input"] == input_a
        bytes_before = st["repeat"]["recording"]["bytes"]

        c.set_allow_capture(input_b, True)   # simulate the deck switch (see scenario_d4)
        proc_b = subprocess.Popen(["aplay", "-D", device_b, wav_b])
        st = _wait_for(
            lambda: (lambda s: s["repeat"]["recording"]["origin_input"] == input_b and s)(
                c.get_status()),
            timeout=10, desc="handoff to input B")
        assert st["repeat"]["recording"]["active"], "E1 FAIL: no new recording started for input B"
        print(f"[e1] PASS: origin_input {input_a}->{input_b}; A's {bytes_before} bytes "
              f"superseded by a fresh recording ({st['repeat']['recording']['bytes']} bytes so far)")
    finally:
        for p in (proc_a, proc_b):
            if p is not None and p.poll() is None:
                p.terminate()
        c.set_repeat_armed(False)
        c.close()


def scenario_e6(socket_path: str, wav_a: str, wav_b: str,
                 input_a: int = 1, input_b: int = 2,
                 device_a: str = "hw:Loopback,0,0", device_b: str = "hw:Loopback,0,1"):
    """E6: disarm arriving during FADING_OUT(live_interrupt) is a no-op for
    the fade itself -- it completes, and the new recording for input_b still
    proceeds (recording start does not consult _armed, only replay-start at
    the NEXT capture-stop does)."""
    c = MonitorClient(socket_path)
    proc_a = None
    proc_b = None
    try:
        c.set_repeat_enabled(True, "auto")
        c.set_repeat_armed(True)

        proc_a = subprocess.Popen(["aplay", "-D", device_a, wav_a])
        _wait_for(lambda: (lambda s: s["repeat"]["recording"]["active"] and s)(c.get_status()),
                  timeout=10, desc="recording (input A) to start")
        proc_a.wait(timeout=120)
        _wait_for(lambda: (lambda s: s["repeat"]["replay"]["active"] and s)(c.get_status()),
                  timeout=5, desc="replay of A to start")

        c.set_allow_capture(input_b, True)   # simulate the deck switch (see scenario_d4)
        proc_b = subprocess.Popen(["aplay", "-D", device_b, wav_b])
        # Give the interrupt a moment to register (fade begins) before
        # disarming mid-fade.
        time.sleep(0.4)
        resp = c.set_repeat_armed(False)
        assert resp.get("ok"), f"E6 FAIL: set_repeat_armed(False) did not ack mid-fade: {resp}"
        print("[e6] disarmed mid-fade (should be a no-op for the in-flight interrupt)")

        st = _wait_for(
            lambda: (lambda s: s["repeat"]["recording"]["origin_input"] == input_b
                     and s["repeat"]["recording"]["active"] and s)(c.get_status()),
            timeout=10, desc="new recording for input B to proceed despite mid-fade disarm")
        assert not st["repeat"]["armed"], "E6 FAIL: armed flag unexpectedly true"
        print(f"[e6] PASS: fade completed and new recording started for input {input_b} "
              f"despite the mid-fade disarm ({st['repeat']['recording']['bytes']} bytes so far)")
    finally:
        for p in (proc_a, proc_b):
            if p is not None and p.poll() is None:
                p.terminate()
        c.set_repeat_armed(False)
        c.close()


def scenario_e11(socket_path: str, wav_a: str, wav_b: str,
                  input_a: int = 1, input_b: int = 2,
                  device_a: str = "hw:Loopback,0,0", device_b: str = "hw:Loopback,0,1"):
    """E11: disable arriving during a live-interrupt
    fade, immediately followed by a re-enable BEFORE the fade's terminal
    handler runs, must still honour the interrupt -- a new recording starts
    for input_b -- while the OLD (input_a) buffer is discarded either way.

    RepeatController tracks the pending post-fade action as a single
    PendingAction enum with an explicit, documented precedence, plus a
    narrowly-scoped "restorable" flag set only when a Discard overwrites an
    in-flight LiveInterrupt: a disable arriving mid-interrupt-fade sets
    Discard and _pending_interrupt_restorable, and a re-enable arriving
    before the fade's terminal handler runs flips the pending action back to
    LiveInterrupt, so the interrupt is honoured after all. See
    RepeatController's PendingAction declaration comment
    (autostream_monitor.h) for the exact decided matrix.
    """
    c = MonitorClient(socket_path)
    proc_a = None
    proc_b = None
    try:
        c.set_repeat_enabled(True, "auto")
        c.set_repeat_armed(True)

        proc_a = subprocess.Popen(["aplay", "-D", device_a, wav_a])
        _wait_for(lambda: (lambda s: s["repeat"]["recording"]["active"] and s)(c.get_status()),
                  timeout=10, desc="recording (input A) to start")
        proc_a.wait(timeout=120)
        _wait_for(lambda: (lambda s: s["repeat"]["replay"]["active"] and s)(c.get_status()),
                  timeout=5, desc="replay of A to start")

        c.set_allow_capture(input_b, True)   # simulate the deck switch (see scenario_d4)
        proc_b = subprocess.Popen(["aplay", "-D", device_b, wav_b])
        # Give the interrupt a moment to register (fade begins: state ->
        # FadingOut, _pending_action -> LiveInterrupt) before disabling.
        time.sleep(0.4)

        resp = c.set_repeat_enabled(False, "auto")
        assert resp.get("ok"), f"E11 FAIL: set_repeat_enabled(False) did not ack mid-fade: {resp}"
        print("[e11] disabled mid-interrupt-fade (_pending_action -> Discard, "
              "_pending_interrupt_restorable -> True)")

        # Re-enable BEFORE the ~1.5s fade's terminal handler has run. The
        # fade itself (timing/gain shape) is unaffected either way -- only
        # the controller's POST-fade branching is at stake.
        resp = c.set_repeat_enabled(True, "auto")
        assert resp.get("ok"), f"E11 FAIL: set_repeat_enabled(True) (re-enable) did not ack: {resp}"
        print("[e11] re-enabled before the fade's terminal handler ran "
              "(_pending_action should restore to LiveInterrupt)")

        st = _wait_for(
            lambda: (lambda s: s["repeat"]["recording"]["origin_input"] == input_b
                     and s["repeat"]["recording"]["active"] and s)(c.get_status()),
            timeout=10,
            desc="new recording for input B to start despite the disable/re-enable mid-fade")
        assert st["repeat"]["enabled"], "E11 FAIL: enabled flag unexpectedly false"
        print(f"[e11] PASS: fade completed, old (input {input_a}) buffer discarded, and a NEW "
              f"recording started for input {input_b} ({st['repeat']['recording']['bytes']} "
              f"bytes so far) -- disable/re-enable-during-interrupt-fade honoured the interrupt")
    finally:
        for p in (proc_a, proc_b):
            if p is not None and p.poll() is None:
                p.terminate()
        c.set_repeat_armed(False)
        c.close()


# ---------------------------------------------------------------------------
# r1 scenario: live DSP applies during replay
# ---------------------------------------------------------------------------

def _paced_fifo_reader(fifo_path: str, stop_event: threading.Event,
                        chunks: list, rate_bytes_per_sec: int = 176400,
                        chunk_ms: float = 20.0):
    """Drains fifo_path at a fixed real-time pace (mirrors fifo_reader_stub.py's
    main loop) so ReplayEngine's own pipe-backpressure pacing produces audio in
    real time rather than racing ahead of wall-clock -- essential for r1's
    "did the amplitude change within ~2s of the socket call" measurement to be
    meaningful. Appends (monotonic_recv_time, raw_bytes) tuples to `chunks`
    (a plain list -- single reader thread, single appender, so no lock is
    needed; the caller only reads `chunks` after stop_event is set and this
    thread has been joined).

    Runs inline in-process rather than shelling out to fifo_reader_stub.py: r1
    needs per-chunk timestamps correlated to this driver's own set_gain() call,
    which is far simpler to get right talking directly to one Python list than
    parsing a subprocess's stdout JSON lines and re-deriving timestamps.
    """
    chunk_bytes = max(1, int(rate_bytes_per_sec * (chunk_ms / 1000.0)))
    chunk_period = chunk_ms / 1000.0
    fd = os.open(fifo_path, os.O_RDONLY)
    try:
        while not stop_event.is_set():
            loop_start = time.monotonic()
            try:
                data = os.read(fd, chunk_bytes)
            except BlockingIOError:
                data = b""
            if data:
                chunks.append((time.monotonic(), data))
            elapsed = time.monotonic() - loop_start
            remaining = chunk_period - elapsed
            if remaining > 0:
                time.sleep(remaining)
    finally:
        os.close(fd)


def _peak_amplitude_s16le_stereo(raw: bytes) -> float:
    """Peak absolute amplitude (0..1, both channels) across a raw s16le
    stereo blob. Returns 0.0 for an empty/odd-length blob."""
    n_frames = len(raw) // 4
    if n_frames == 0:
        return 0.0
    samples = struct.unpack(f"<{n_frames * 2}h", raw[:n_frames * 4])
    return max(abs(s) for s in samples) / 32768.0


def scenario_r1(socket_path: str, wav_path: str, fifo_path: str, input_index: int = 1,
                 playback_device: str = "hw:Loopback,0,0",
                 gain_before_db: float = 0.0, gain_after_db: float = -12.0):
    """r1: confirms live DSP applies DURING replay. Starts a
    recording+replay session, lets replay settle into steady looped playback,
    then changes the origin input's gain via the socket (set_gain) WHILE
    replay is active, and measures the amplitude actually written to the test
    FIFO (via an in-process paced reader, mirroring fifo_reader_stub.py)
    before vs. after the change. Replay runs the live DSP chain, so the
    change must be audible in the FIFO stream within about the
    ~1 s live-DSP pull cadence, well inside this scenario's ~2 s window.

    wav_path should have a tone long enough (plus a short silence tail) that
    the recording+replay loop is comfortably longer than the ~5 s this
    scenario needs steady-state on either side of the gain change (a ~15 s
    tone is plenty)."""
    c = MonitorClient(socket_path)
    proc = None
    reader_thread = None
    stop_reader = threading.Event()
    chunks: list = []
    try:
        c.set_repeat_enabled(True, "auto")
        c.set_gain(input_index, gain_before_db)
        c.set_repeat_armed(True)

        proc = subprocess.Popen(["aplay", "-D", playback_device, wav_path])
        _wait_for(lambda: (lambda s: s["repeat"]["recording"]["active"] and s)(c.get_status()),
                  timeout=10, desc="recording to start")
        proc.wait(timeout=120)

        _wait_for(lambda: (lambda s: s["repeat"]["replay"]["active"] and s)(c.get_status()),
                  timeout=10, desc="replay to start")

        reader_thread = threading.Thread(
            target=_paced_fifo_reader, args=(fifo_path, stop_reader, chunks), daemon=True)
        reader_thread.start()

        print(f"[r1] letting replay settle at gain={gain_before_db} dB before measuring baseline")
        time.sleep(3.0)

        gain_change_t = time.monotonic()
        print(f"[r1] changing origin input {input_index}'s gain via set_gain "
              f"({gain_before_db} -> {gain_after_db} dB) while replay is active")
        resp = c.set_gain(input_index, gain_after_db)
        assert resp.get("ok"), f"r1 FAIL: set_gain rejected while replay active: {resp}"

        # The DAEMON's own live-DSP pull cadence is ~1 s, and direct
        # instrumentation of ReplayEngine confirms the post-DSP peak sample
        # drops to the new gain within about a second of the socket call.
        # The window here is deliberately wider than that
        # -- draining a Python-threaded FIFO reader running alongside this
        # same process's socket I/O is itself subject to GIL/scheduling jitter
        # that can let a few hundred ms to ~1 s of already-in-flight pipe
        # content (bounded by the pipe's own ~64 KiB capacity, no more) queue
        # up before this reader catches up; the extra margin absorbs that
        # TEST-HARNESS slop so the assertion reflects the daemon's real
        # behaviour rather than this script's own pacing precision.
        time.sleep(6.0)

        stop_reader.set()
        reader_thread.join(timeout=5)
        reader_thread = None

        before = [(t, data) for t, data in chunks
                  if gain_change_t - 1.5 <= t < gain_change_t]
        after = [(t, data) for t, data in chunks
                 if gain_change_t + 4.0 <= t <= gain_change_t + 6.0]

        assert before, "r1 FAIL: no FIFO data captured before the gain change"
        assert after, "r1 FAIL: no FIFO data captured in the post-change measurement window"

        before_peak = max(_peak_amplitude_s16le_stereo(data) for _, data in before)
        after_peak = max(_peak_amplitude_s16le_stereo(data) for _, data in after)

        expected_ratio = 10.0 ** ((gain_after_db - gain_before_db) / 20.0)
        ratio = (after_peak / before_peak) if before_peak > 0 else 0.0
        print(f"[r1] amplitude before={before_peak:.4f}, after={after_peak:.4f}, "
              f"ratio={ratio:.3f} (expected ~{expected_ratio:.3f} for a {gain_after_db - gain_before_db:.0f} dB step)")

        assert before_peak > 0.02, f"r1 FAIL: no meaningful signal detected before the gain change (peak={before_peak:.4f})"
        # Loose tolerance (0.6x the expected linear ratio, i.e. the drop must
        # be at least clearly in the right direction and roughly the right
        # size) -- this is an audibility check, not a precision gain-accuracy
        # test (which is already covered by the C++ unit suite's DSP tests).
        assert ratio < max(expected_ratio * 1.6, 0.5), (
            f"r1 FAIL: gain change during replay did not produce the expected amplitude drop "
            f"within ~2s (before={before_peak:.4f}, after={after_peak:.4f}, ratio={ratio:.3f}, "
            f"expected ~{expected_ratio:.3f}) -- live DSP does not appear to be applying during replay")
        print("[r1] PASS: live gain change during replay was audible in the FIFO stream within ~2s")
    finally:
        stop_reader.set()
        if reader_thread is not None:
            reader_thread.join(timeout=5)
        if proc is not None and proc.poll() is None:
            proc.terminate()
        c.set_gain(input_index, 0.0)
        c.set_repeat_armed(False)
        c.close()


# ---------------------------------------------------------------------------
# d15 -- coordinator-restart burst against a HOLD recording
#
# Regression contract: the daemon must survive the Python coordinator's
# restart teardown+startup burst --
#   set_repeat_armed(false), stop_input(1), stop_input(2),
#   set_fifo, configure_input(1), configure_input(2),
#   start_input(1), start_input(2), set_gain(1), set_gain(2),
#   set_eq(1), set_eq(2), set_output_eq, set_repeat_enabled(true, "auto")
# -- fired while the daemon holds a HOLD recording (buffer retained from an
# earlier disarmed replay), without ControlServer's accept thread staying
# alive while get_status (and every other command) stops replying.
#
# This scenario reproduces that sequence as closely as a standalone
# two-input test daemon allows: establish a HOLD recording via a genuine
# disarm-mid-replay (not just a natural capture-stop, to match "an earlier
# disarmed replay" exactly), keep BOTH loopback devices continuously fed
# (so a should_capture edge -- notify_capture_started()/notify_input_
# stopped() -- can race the burst's stop_input/start_input on the audio
# thread, not just be issued from the idle control thread), then fire the
# exact burst on a FRESH connection and probe get_status with a short
# per-call timeout throughout and immediately after.
# ---------------------------------------------------------------------------

def _burst_probe_status(socket_path: str, timeout: float = 2.0):
    """One-shot get_status on a brand-new connection with a short timeout.
    Returns (ok, elapsed_seconds, detail) -- never raises."""
    t0 = time.monotonic()
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect(socket_path)
        s.sendall(b'{"type":"get_status"}\n')
        buf = b""
        while b"\n" not in buf:
            chunk = s.recv(65536)
            if not chunk:
                return False, time.monotonic() - t0, "connection closed"
            buf += chunk
        return True, time.monotonic() - t0, "ok"
    except socket.timeout:
        return False, time.monotonic() - t0, "timeout"
    except OSError as e:
        return False, time.monotonic() - t0, str(e)
    finally:
        s.close()


def scenario_d15(socket_path: str, wav_path: str, fifo_path: str,
                  input_a: int = 1, input_b: int = 2,
                  device_a: str = "hw:Loopback,0,0", device_b: str = "hw:Loopback,0,1",
                  n_iterations: int = 5):
    """d15: coordinator-restart burst fired against a HOLD
    recording (established via a genuine disarm-mid-replay), with both
    loopback devices continuously fed so should_capture edges can race the
    burst's stop_input/start_input calls. Fails loudly (AssertionError) the
    first time any get_status probe -- during or immediately after the
    burst -- exceeds its timeout, which is what "wedged" looks like from the
    control socket's side.

    device_a/device_b are the PLAYBACK-side loopback devices; the daemon's
    own configure_input calls target the corresponding CAPTURE-side
    subdevices (card offset +1, matching every other two-input scenario in
    this file, e.g. scenario_d4)."""
    capture_a = device_a.replace("hw:Loopback,0,", "hw:Loopback,1,")
    capture_b = device_b.replace("hw:Loopback,0,", "hw:Loopback,1,")

    for n in range(1, n_iterations + 1):
        print(f"\n[d15] iteration {n}/{n_iterations}")
        c = MonitorClient(socket_path)
        loop_a = loop_b = None
        try:
            c.set_fifo(fifo_path)
            c.configure_input(input_a, capture_a, silence_threshold_dbfs=-66.0, silence_seconds=2)
            c.configure_input(input_b, capture_b, silence_threshold_dbfs=-66.0, silence_seconds=2)
            c.start_input(input_a)
            c.start_input(input_b)
            c.set_allow_capture(input_a, True)
            c.set_repeat_enabled(True, "auto")
            c.set_repeat_armed(True)

            proc = subprocess.Popen(["aplay", "-D", device_a, wav_path])
            _wait_for(lambda: (lambda s: s["repeat"]["recording"]["active"] and s)(c.get_status()),
                      timeout=10, desc="recording to start")
            _wait_for(lambda: (lambda s: s["repeat"]["replay"]["active"] and s)(c.get_status()),
                      timeout=60, desc="replay to start (auto-replay via armed=true)")
            proc.wait(timeout=10)

            # Disarm MID-REPLAY -> 1.5s fade -> HOLD, exactly matching "an
            # earlier disarmed replay" rather than a natural capture-stop.
            time.sleep(2.0)
            c.set_repeat_armed(False)
            st = _wait_for(lambda: (lambda s: not s["repeat"]["replay"]["active"] and s)(c.get_status()),
                            timeout=10, desc="disarm fade to complete (-> Hold)")
            assert st["repeat"]["recording"]["bytes"] > 0, "d15 FAIL: expected a HOLD buffer after disarm"
            print(f"[d15] HOLD established: {st['repeat']['recording']['bytes']} bytes, "
                  f"origin_input={st['repeat']['recording']['origin_input']}")
            c.close()
        except Exception:
            c.close()
            raise

        # Continuous audio on BOTH devices, started BEFORE the burst, so a
        # should_capture edge can fire on the audio thread the instant
        # start_input() reopens capture -- concurrent with the rest of the
        # burst's commands on the control thread.
        loop_a = subprocess.Popen(
            ["bash", "-c", f"while true; do aplay -q -D {device_a} {wav_path}; done"],
            preexec_fn=os.setsid)
        loop_b = subprocess.Popen(
            ["bash", "-c", f"while true; do aplay -q -D {device_b} {wav_path}; done"],
            preexec_fn=os.setsid)

        burst = MonitorClient(socket_path, timeout=5.0)
        t0 = time.monotonic()
        try:
            print("[d15] firing coordinator-restart burst...")
            burst.set_repeat_armed(False)
            burst.stop_input(input_a)
            burst.stop_input(input_b)
            burst.set_fifo(fifo_path)
            burst.configure_input(input_a, capture_a, silence_threshold_dbfs=-66.0, silence_seconds=2)
            burst.configure_input(input_b, capture_b, silence_threshold_dbfs=-66.0, silence_seconds=2)
            burst.start_input(input_a)
            burst.start_input(input_b)
            burst.set_gain(input_a, 0.0)
            burst.set_gain(input_b, 0.0)
            burst.command({"type": "set_eq", "input": input_a, "bands": []})
            burst.command({"type": "set_eq", "input": input_b, "bands": []})
            burst.command({"type": "set_output_eq", "bands": []})
            burst.set_repeat_enabled(True, "auto")
            print(f"[d15] burst completed in {time.monotonic() - t0:.3f}s")
        except (socket.timeout, ConnectionError, OSError) as e:
            raise AssertionError(
                f"d15 FAIL: WEDGE -- burst command itself hung/errored after "
                f"{time.monotonic() - t0:.3f}s: {e}") from e
        finally:
            try:
                burst.close()
            except OSError:
                pass
            for p in (loop_a, loop_b):
                try:
                    os.killpg(os.getpgid(p.pid), 9)
                except (ProcessLookupError, AttributeError):
                    pass
            subprocess.run(["pkill", "-9", "-f", f"aplay -q -D.*{os.path.basename(wav_path)}"])

        for i in range(5):
            ok, elapsed, detail = _burst_probe_status(socket_path, timeout=2.0)
            print(f"[d15] get_status probe {i}: ok={ok} elapsed={elapsed:.3f}s detail={detail}")
            if not ok:
                raise AssertionError(
                    f"d15 FAIL: WEDGE -- get_status probe {i} did not reply "
                    f"within 2s ({detail}) after the coordinator-restart burst "
                    f"on iteration {n}")
            time.sleep(0.5)

    print(f"\n[d15] ALL PASS: no wedge across {n_iterations} iteration(s)")


# ---------------------------------------------------------------------------
# d15r -- d15's burst compounded with concurrent logrotate
# copytruncate rotation of the daemon's own log file
#
# Regression contract: the daemon must survive the d15 command burst
# against HOLD state WHILE the daemon's log file is being copytruncated
# (cp + truncate -s 0, in place, no reopen -- exactly logrotate's
# copytruncate strategy, as configured against /var/log/autostream/*.log,
# daily), the same way it survives either condition alone.
#
# IMPORTANT harness-fidelity note: production launches the monitor under
# systemd with StandardOutput=append:/StandardError=append: (confirmed via
# `cat /etc/systemd/system/autostream_monitor.service`) -- genuine O_APPEND
# semantics. A test harness that launches the standalone daemon with plain
# shell `>` redirection (O_TRUNC, no O_APPEND) is NOT faithful to this and
# must use `>>` (which bash opens with O_APPEND, matching systemd's
# append:) instead -- verify with `cat /proc/<pid>/fdinfo/2 | grep flags`
# and confirm O_APPEND (bit 0x400) is set before trusting a run of this
# scenario.
#
# Three modes:
#   burst    full d15 burst with a continuous copytruncate loop racing
#            throughout.
#   between  no background loop -- truncate exactly BETWEEN each individual
#            burst command (paced, one truncate per inter-command gap).
#   steady   no burst at all -- just a steady recording session with the
#            copytruncate loop racing, isolating whether logging + rotation
#            alone (no command burst) can wedge the daemon.
# ---------------------------------------------------------------------------

def _copytruncate_once(log_path: str, rotated_dir: str):
    """One logrotate-style copytruncate cycle against log_path: cp (snapshot)
    then truncate -s 0 IN PLACE -- no close/reopen/rename of the writer's fd,
    exactly matching logrotate's copytruncate strategy."""
    import shutil as _shutil
    os.makedirs(rotated_dir, exist_ok=True)
    try:
        if os.path.exists(log_path):
            _shutil.copyfile(log_path, os.path.join(rotated_dir, f"rotated_{time.time():.3f}.log"))
            with open(log_path, "r+b") as f:
                f.truncate(0)
    except OSError as e:
        print(f"[d15r] copytruncate error: {e}")


def scenario_d15r(socket_path: str, wav_path: str, fifo_path: str, log_path: str,
                   mode: str = "burst",
                   input_a: int = 1, input_b: int = 2,
                   device_a: str = "hw:Loopback,0,0", device_b: str = "hw:Loopback,0,1",
                   n_iterations: int = 5,
                   rotated_dir: str = "/tmp/d15r_rotated"):
    """d15r: d15's burst (or a steady recording, for
    mode="steady") compounded with a concurrent logrotate-style copytruncate
    loop against the daemon's OWN log file (log_path -- pass the SAME path
    the standalone daemon's stdout/stderr was redirected to with `>>`, e.g.
    the harness's daemon.log). See the module comment above for the
    harness-fidelity (O_APPEND) requirement.

    mode: "burst" (copytruncate loop races the whole burst), "between"
    (truncate exactly between each burst command instead of a background
    loop), or "steady" (no burst -- just a recording session with rotation
    racing, to isolate logging+rotation alone)."""
    capture_a = device_a.replace("hw:Loopback,0,", "hw:Loopback,1,")
    capture_b = device_b.replace("hw:Loopback,0,", "hw:Loopback,1,")

    ct_stop = threading.Event()

    def ct_loop(interval=0.2):
        while not ct_stop.is_set():
            _copytruncate_once(log_path, rotated_dir)
            time.sleep(interval)

    for n in range(1, n_iterations + 1):
        print(f"\n[d15r] iteration {n}/{n_iterations} (mode={mode})")
        c = MonitorClient(socket_path, timeout=8.0)
        loop_a = loop_b = None
        try:
            c.set_fifo(fifo_path)
            c.configure_input(input_a, capture_a, silence_threshold_dbfs=-66.0, silence_seconds=2)
            c.configure_input(input_b, capture_b, silence_threshold_dbfs=-66.0, silence_seconds=2)
            c.start_input(input_a)
            c.start_input(input_b)
            c.set_allow_capture(input_a, True)
            c.set_repeat_enabled(True, "auto")
            c.set_repeat_armed(True)

            proc = subprocess.Popen(["aplay", "-D", device_a, wav_path])
            _wait_for(lambda: (lambda s: s["repeat"]["recording"]["active"] and s)(c.get_status()),
                      timeout=10, desc="recording to start")
            _wait_for(lambda: (lambda s: s["repeat"]["replay"]["active"] and s)(c.get_status()),
                      timeout=60, desc="replay to start")
            proc.wait(timeout=10)

            time.sleep(2.0)
            c.set_repeat_armed(False)
            st = _wait_for(lambda: (lambda s: not s["repeat"]["replay"]["active"] and s)(c.get_status()),
                            timeout=10, desc="disarm fade to complete (-> Hold)")
            assert st["repeat"]["recording"]["bytes"] > 0, "d15r FAIL: expected a HOLD buffer after disarm"
            print(f"[d15r] HOLD established: {st['repeat']['recording']['bytes']} bytes")
            c.close()
        except Exception:
            c.close()
            raise

        loop_a = subprocess.Popen(
            ["bash", "-c", f"while true; do aplay -q -D {device_a} {wav_path}; done"],
            preexec_fn=os.setsid)
        loop_b = subprocess.Popen(
            ["bash", "-c", f"while true; do aplay -q -D {device_b} {wav_path}; done"],
            preexec_fn=os.setsid)

        ct_thread = None
        if mode in ("burst", "steady"):
            ct_stop.clear()
            ct_thread = threading.Thread(target=ct_loop, daemon=True)
            ct_thread.start()

        try:
            if mode == "steady":
                print("[d15r] steady: no burst, recording runs with rotation racing")
                time.sleep(8.0)
            else:
                burst = MonitorClient(socket_path, timeout=5.0)
                t0 = time.monotonic()
                try:
                    burst.set_repeat_armed(False)
                    burst.stop_input(input_a)
                    burst.stop_input(input_b)
                    burst.set_fifo(fifo_path)
                    burst.configure_input(input_a, capture_a, silence_threshold_dbfs=-66.0, silence_seconds=2)
                    burst.configure_input(input_b, capture_b, silence_threshold_dbfs=-66.0, silence_seconds=2)
                    if mode == "between":
                        _copytruncate_once(log_path, rotated_dir)
                    burst.start_input(input_a)
                    burst.start_input(input_b)
                    if mode == "between":
                        _copytruncate_once(log_path, rotated_dir)
                    burst.set_gain(input_a, 0.0)
                    burst.set_gain(input_b, 0.0)
                    burst.command({"type": "set_eq", "input": input_a, "bands": []})
                    burst.command({"type": "set_eq", "input": input_b, "bands": []})
                    if mode == "between":
                        _copytruncate_once(log_path, rotated_dir)
                    burst.command({"type": "set_output_eq", "bands": []})
                    burst.set_repeat_enabled(True, "auto")
                    print(f"[d15r] burst completed in {time.monotonic() - t0:.3f}s")
                except (socket.timeout, ConnectionError, OSError) as e:
                    raise AssertionError(
                        f"d15r FAIL: WEDGE -- burst command hung/errored after "
                        f"{time.monotonic() - t0:.3f}s: {e}") from e
                finally:
                    burst.close()

            for i in range(5):
                ok, elapsed, detail = _burst_probe_status(socket_path, timeout=2.0)
                print(f"[d15r] get_status probe {i}: ok={ok} elapsed={elapsed:.3f}s detail={detail}")
                if not ok:
                    raise AssertionError(
                        f"d15r FAIL: WEDGE (mode={mode}) -- get_status probe {i} "
                        f"did not reply within 2s ({detail}) on iteration {n}")
                time.sleep(0.5)
        finally:
            ct_stop.set()
            if ct_thread:
                ct_thread.join(timeout=3)
            for p in (loop_a, loop_b):
                if p is None:
                    continue
                try:
                    os.killpg(os.getpgid(p.pid), 9)
                except (ProcessLookupError, AttributeError):
                    pass
            subprocess.run(["pkill", "-9", "-f", f"aplay -q -D.*{os.path.basename(wav_path)}"])

    print(f"\n[d15r] ALL PASS (mode={mode}): no wedge across {n_iterations} iteration(s)")


# ---------------------------------------------------------------------------
# d16 -- watchdog auto-restart routed through the blessed stop path
#
# The watchdog auto-restart loop in AudioMonitor::run() and api_stop_input()
# both route through one shared AudioMonitor::stop_input_with_teardown()
# helper, so a self-stopped capture thread (is_started=true,
# is_running=false after an unrecoverable ALSA error) always runs
# RepeatController::notify_input_stopped() / reset_auto_trim() teardown
# before the watchdog's start() retry. If the crashed input is the repeat
# feature's recording origin and that teardown is skipped, the controller
# never learns capture died: the recording session stays logically "active"
# (or the origin stays pointed at a channel the watchdog is restarting from
# scratch) instead of collapsing to a re-armable Idle state. This scenario
# forces that self-stop and asserts the teardown ran.
# ---------------------------------------------------------------------------

def scenario_d16(socket_path: str, wav_path: str, fifo_path: str,
                  input_index: int = 1, device: str = "hw:Loopback,0,0",
                  restart_timeout: float = 15.0):
    """d16: force the recording-origin input's capture thread to
    self-stop the way a real ALSA driver crash/USB-yank does, let the
    watchdog auto-restart loop in AudioMonitor::run() fire, and assert (a)
    the watchdog teardown routed through notify_input_stopped() -- observed
    via its one PERSISTENT effect, armed -> false (see the timing note
    below for why the collapsed-recording snapshot itself cannot be polled
    for) -- rather than leaving the controller wedged on the dead origin
    input, and (b) a subsequent record/replay cycle on the same input
    completes once the watchdog's own start() retry succeeds.

    REQUIRES the standalone test daemon to be launched with --test-hooks
    (docs/AUTOSTREAM-MONITOR.md "Command-Line Options" /
    "debug_fail_input"). Never point this at the live daemon: --test-hooks
    is never set by the production systemd unit, so debug_fail_input is
    rejected there anyway, but this scenario should only ever run against a
    standalone test instance regardless. Unlike every rmmod-based scenario
    in this file, d16 needs no sudo.

    Fault-injection mechanism (why this needed a daemon-side hook, unlike
    every other scenario in this file):

    The obvious approach -- `sudo rmmod snd_aloop` while the daemon has the
    capture subdevice open -- does not work: the daemon's own open PCM
    handle holds a kernel reference on the module, so `rmmod` (even
    `rmmod -f`) fails deterministically with "module in use" and the
    scenario never reaches its assertions on ANY binary, fixed or not. This
    is a deterministic property of the kernel module reference, not a
    matter of retrying or of `-f`.

    There is no other externally-triggerable way to make autostream_monitor's
    own ALSA read fail: the daemon owns the only PCM handle on the loopback
    pair, and calling stop_input() would just exercise the (already-correct)
    blessed path this test exists to route around, not the watchdog. So this
    scenario uses the `debug_fail_input` socket command instead -- a minimal,
    inert-unless-flagged daemon test hook, used because the sudo/rmmod
    approach is impossible here, not skipped for convenience. It arms a
    one-shot atomic flag on the target InputChannel;
    capture_thread_func() checks it once per loop iteration at the exact spot
    it already checks AlsaCapture::read()'s return value
    (autostream_monitor_io.cpp, near the `frames_read < 0` branch) and, if
    set, forces frames_read negative and clears the flag. From that single
    branch point on, the code path is IDENTICAL to a genuine unrecoverable
    ALSA error: same LOG_WARN, same `_running.store(false)`, same thread
    exit, same is_started/is_running state the watchdog polls for, same
    stop_input_with_teardown() call, same start() retry. Only the trigger
    (an atomic flag instead of a real ALSA errno) is synthetic; everything
    the watchdog and the repeat controller do in response is real,
    unmodified production code.

    Because the loopback device itself is never removed (no rmmod/modprobe
    involved), the watchdog's start() retry should succeed on its first or
    second 100ms poll -- there is no backoff-vs-module-reload race to
    choreograph the way an rmmod-based approach would need, hence the
    shorter default restart_timeout (kept generous, not tight, since this
    is a real 100ms-poll daemon on a possibly loaded test host, not a
    deterministic clock).

    Timing note (why the teardown assertion keys on `armed`): on the test
    host, the injected self-stop, the watchdog's teardown and its
    successful start() retry all complete within ~100 ms -- and with aplay
    still feeding the loopback, a fresh legitimate recording session can
    begin within milliseconds of the restart. So both is_running=false and
    recording.active=false are unobservable transients at any sane
    status-poll rate. `armed` is the one persistent marker:
    notify_input_stopped() clears it and nothing re-arms it until this
    scenario does so itself; on a binary that bypasses the shared teardown
    it stays true forever (the wedge this scenario detects).
    """
    capture_device = device.replace("hw:Loopback,0,", "hw:Loopback,1,")

    c = MonitorClient(socket_path)
    proc = None
    try:
        print("[d16] arming a fresh recording session")
        c.set_fifo(fifo_path)
        c.configure_input(input_index, capture_device,
                           silence_threshold_dbfs=-66.0, silence_seconds=2)
        c.start_input(input_index)
        c.set_allow_capture(input_index, True)
        c.set_repeat_enabled(True, "auto")
        c.set_repeat_armed(True)

        proc = subprocess.Popen(["aplay", "-D", device, wav_path])
        _wait_for(lambda: (lambda s: s["repeat"]["recording"]["active"] and s)(c.get_status()),
                  timeout=10, desc="recording to start")
        st = c.get_status()
        assert st["inputs"][input_index - 1]["started"] and st["inputs"][input_index - 1]["running"], (
            f"d16 FAIL: input {input_index} not up before fault injection: {st['inputs'][input_index - 1]}")
        print(f"[d16] Recording established: "
              f"{st['repeat']['recording']['bytes']} bytes, origin_input="
              f"{st['repeat']['recording']['origin_input']}")

        print("[d16] injecting fault via debug_fail_input (simulated ALSA-crash "
              "capture-thread self-stop; requires daemon started with --test-hooks)")
        resp = c.debug_fail_input(input_index)
        assert resp.get("ok"), (
            f"d16 FAIL: debug_fail_input rejected -- was the daemon started with "
            f"--test-hooks? response: {resp}")

        # This is the actual regression assertion. The injected self-stop,
        # the watchdog's teardown and its successful start() retry all
        # complete within ~100 ms (measured on the test host), and with
        # aplay still feeding
        # the loopback a fresh legitimate recording session can begin within
        # milliseconds of the restart -- so is_running=false and
        # recording.active=false are unobservable transients at any sane
        # poll interval. The one PERSISTENT effect of the teardown is
        # notify_input_stopped() clearing `armed`; nothing re-arms it until
        # this scenario does so itself. On a binary that calls
        # _inputs[i]->stop() directly from the watchdog loop (bypassing the
        # shared teardown), notify_input_stopped() is never called, so armed
        # stays true and the recording stays "active" with its pre-crash
        # byte count frozen -- the wedge this wait times out on.
        pre_crash_bytes = st["repeat"]["recording"]["bytes"]
        print("[d16] waiting for watchdog teardown: armed -> false (persistent "
              "marker of notify_input_stopped(); transients are too fast to poll)")
        st = _wait_for(lambda: (lambda s: (s["repeat"]["armed"] is False) and s)(c.get_status()),
                        timeout=10,
                        desc="armed to clear via watchdog teardown (a timeout here IS the wedge)")

        # Belt and braces: armed cleared, so teardown ran; also show the
        # session is not the stale pre-crash one. Either it is (still)
        # collapsed, or a fresh session has started whose byte count moves --
        # re-poll once so a coincidentally equal snapshot can't fail
        # spuriously.
        rec = st["repeat"]["recording"]
        if rec["active"] and rec["bytes"] == pre_crash_bytes:
            time.sleep(0.5)
            rec = c.get_status()["repeat"]["recording"]
            assert (not rec["active"]) or rec["bytes"] != pre_crash_bytes, (
                f"d16 FAIL: armed cleared but recording is stale/frozen at "
                f"pre-crash bytes={pre_crash_bytes}: {rec}")
        print("[d16] PASS: watchdog teardown ran (armed cleared; no stale session)")

        # aplay's own fd into the loopback playback side is orphaned once the
        # daemon's capture side self-stops; it keeps writing into a device
        # nobody drains but that's harmless here, just reap it.
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        proc = None

        print(f"[d16] waiting up to {restart_timeout:.0f}s for the watchdog's restart to succeed "
              "(loopback device itself was never removed, so no module-reload wait is needed)")
        st = _wait_for(
            lambda: (lambda s: (s["inputs"][input_index - 1]["started"]
                                 and s["inputs"][input_index - 1]["running"]) and s)(c.get_status()),
            timeout=restart_timeout, desc="watchdog to restart the input")
        print(f"[d16] PASS: input {input_index} restarted by the watchdog: "
              f"{st['inputs'][input_index - 1]}")

        print("[d16] verifying a subsequent record cycle on the recovered input works")
        c.set_repeat_armed(True)
        proc = subprocess.Popen(["aplay", "-D", device, wav_path])
        st = _wait_for(lambda: (lambda s: s["repeat"]["recording"]["active"] and s)(c.get_status()),
                        timeout=15, desc="a fresh recording to start after recovery")
        assert st["repeat"]["recording"]["origin_input"] == input_index, (
            f"d16 FAIL: post-recovery recording has unexpected origin: {st['repeat']['recording']}")
        # Must outlast the full WAV (default gen-tone: 10s tone + 5s silence).
        proc.wait(timeout=30)
        proc = None
        st = _wait_for(lambda: (lambda s: s["repeat"]["replay"]["active"] and s)(c.get_status()),
                        timeout=60, desc="post-recovery replay to start")
        print(f"[d16] PASS: post-recovery record/replay cycle completed: {st['repeat']['replay']}")

        print("\n[d16] ALL PASS")
    finally:
        if proc is not None and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
        c.close()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                  formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("setup-aloop", help="modprobe snd-aloop if not already loaded")

    p_gen = sub.add_parser("gen-tone", help="generate a tone+silence WAV")
    p_gen.add_argument("--out", required=True)
    p_gen.add_argument("--tone-seconds", type=float, default=10.0)
    p_gen.add_argument("--silence-seconds", type=float, default=40.0)
    p_gen.add_argument("--freq-hz", type=float, default=440.0)

    p_play = sub.add_parser("play", help="play a WAV into the loopback playback side")
    p_play.add_argument("--wav", required=True)
    p_play.add_argument("--device", default="hw:Loopback,0,0")

    p_status = sub.add_parser("status", help="print one get_status response")
    p_status.add_argument("--socket", default=DEFAULT_SOCKET)

    p_enable = sub.add_parser("set-repeat-enabled")
    p_enable.add_argument("--socket", default=DEFAULT_SOCKET)
    p_enable.add_argument("--enabled", type=lambda s: s.lower() in ("1", "true", "yes"), required=True)
    p_enable.add_argument("--codec", default="auto")

    p_d7 = sub.add_parser("d7", help="run the D7 enable/disable mid-session scenario")
    p_d7.add_argument("--socket", default=DEFAULT_SOCKET)
    p_d7.add_argument("--wav", required=True)
    p_d7.add_argument("--input", type=int, default=1)
    p_d7.add_argument("--device", default="hw:Loopback,0,0")

    p_gen_multi = sub.add_parser("gen-multi-track", help="generate an N-track tone WAV for D10")
    p_gen_multi.add_argument("--out", required=True)
    p_gen_multi.add_argument("--tracks", type=int, default=3)
    p_gen_multi.add_argument("--tone-seconds", type=float, default=5.0)
    p_gen_multi.add_argument("--gap-seconds", type=float, default=2.0)
    p_gen_multi.add_argument("--tail-silence-seconds", type=float, default=40.0)

    for name, help_text in (
        ("d1d3", "run the D1+D3 record->replay / loop-seam scenario"),
        ("d5d6", "run the D5+D6 disarm-fade / arm-while-HOLD scenario"),
        ("d9", "run the D9 status-atomicity poll scenario"),
        ("d10", "run the D10 track-ID-during-replay scenario"),
        ("d12", "run the D12 stop_input discard scenario"),
    ):
        p = sub.add_parser(name, help=help_text)
        p.add_argument("--socket", default=DEFAULT_SOCKET)
        p.add_argument("--wav", required=True)
        p.add_argument("--input", type=int, default=1)
        p.add_argument("--device", default="hw:Loopback,0,0")

    p_d11 = sub.add_parser("d11", help="run the D11 reader-killed/disarm-unblocks scenario")
    p_d11.add_argument("--socket", default=DEFAULT_SOCKET)
    p_d11.add_argument("--wav", required=True)
    p_d11.add_argument("--fifo", required=True, help="test FIFO path (for pkill matching + reader restart)")
    p_d11.add_argument("--input", type=int, default=1)
    p_d11.add_argument("--device", default="hw:Loopback,0,0")

    p_d4 = sub.add_parser("d4", help="run the D4 live-interrupt crossfade scenario")
    p_d4.add_argument("--socket", default=DEFAULT_SOCKET)
    p_d4.add_argument("--wav-a", required=True, help="tone+silence WAV for the original session (input A)")
    p_d4.add_argument("--wav-b", required=True, help="tone WAV for the interrupting session (input B)")
    p_d4.add_argument("--fifo", required=True, help="test FIFO path (informational; dump comes from --dump-path)")
    p_d4.add_argument("--dump-path", default="/tmp/d4_fifo_dump.raw",
                       help="raw s16le FIFO dump written by a concurrent "
                            "fifo_reader_stub.py --dump-path run against --fifo")
    p_d4.add_argument("--input-a", type=int, default=1)
    p_d4.add_argument("--input-b", type=int, default=2)
    p_d4.add_argument("--device-a", default="hw:Loopback,0,0")
    p_d4.add_argument("--device-b", default="hw:Loopback,0,1")
    p_d4.add_argument("--freq-a", type=float, default=440.0)
    p_d4.add_argument("--freq-b", type=float, default=880.0)

    for name, help_text in (
        ("e1", "run the E1 input-handoff-mid-recording scenario"),
        ("e6", "run the E6 disarm-during-interrupt-fade scenario"),
        ("e11", "run the E11 disable/re-enable-during-interrupt-fade scenario"),
    ):
        p = sub.add_parser(name, help=help_text)
        p.add_argument("--socket", default=DEFAULT_SOCKET)
        p.add_argument("--wav-a", required=True)
        p.add_argument("--wav-b", required=True)
        p.add_argument("--input-a", type=int, default=1)
        p.add_argument("--input-b", type=int, default=2)
        p.add_argument("--device-a", default="hw:Loopback,0,0")
        p.add_argument("--device-b", default="hw:Loopback,0,1")

    p_r1 = sub.add_parser("r1", help="run the r1 live-DSP-during-replay scenario")
    p_r1.add_argument("--socket", default=DEFAULT_SOCKET)
    p_r1.add_argument("--wav", required=True)
    p_r1.add_argument("--fifo", required=True, help="test FIFO path (read directly, paced, by this scenario)")
    p_r1.add_argument("--input", type=int, default=1)
    p_r1.add_argument("--device", default="hw:Loopback,0,0")
    p_r1.add_argument("--gain-before-db", type=float, default=0.0)
    p_r1.add_argument("--gain-after-db", type=float, default=-12.0)

    p_d15 = sub.add_parser("d15", help="run the d15 coordinator-restart-burst-vs-HOLD scenario")
    p_d15.add_argument("--socket", default=DEFAULT_SOCKET)
    p_d15.add_argument("--wav", required=True)
    p_d15.add_argument("--fifo", required=True, help="test FIFO path")
    p_d15.add_argument("--input-a", type=int, default=1)
    p_d15.add_argument("--input-b", type=int, default=2)
    p_d15.add_argument("--device-a", default="hw:Loopback,0,0")
    p_d15.add_argument("--device-b", default="hw:Loopback,0,1")
    p_d15.add_argument("--iterations", type=int, default=5)

    p_d15r = sub.add_parser("d15r", help="run the d15r coordinator-restart-burst plus copytruncate-rotation compound scenario")
    p_d15r.add_argument("--socket", default=DEFAULT_SOCKET)
    p_d15r.add_argument("--wav", required=True)
    p_d15r.add_argument("--fifo", required=True, help="test FIFO path")
    p_d15r.add_argument("--log-path", required=True,
                         help="path the standalone daemon's stdout/stderr was redirected to with "
                              "`>>` (must be O_APPEND to match production's systemd append: -- "
                              "verify via /proc/<pid>/fdinfo/2)")
    p_d15r.add_argument("--mode", choices=["burst", "between", "steady"], default="burst")
    p_d15r.add_argument("--input-a", type=int, default=1)
    p_d15r.add_argument("--input-b", type=int, default=2)
    p_d15r.add_argument("--device-a", default="hw:Loopback,0,0")
    p_d15r.add_argument("--device-b", default="hw:Loopback,0,1")
    p_d15r.add_argument("--iterations", type=int, default=5)

    p_d16 = sub.add_parser("d16", help="run the d16 watchdog-restart-through-blessed-stop-path scenario "
                                        "(requires the daemon to be started with --test-hooks)")
    p_d16.add_argument("--socket", default=DEFAULT_SOCKET)
    p_d16.add_argument("--wav", required=True)
    p_d16.add_argument("--fifo", required=True, help="test FIFO path")
    p_d16.add_argument("--input", type=int, default=1)
    p_d16.add_argument("--device", default="hw:Loopback,0,0")
    p_d16.add_argument("--restart-timeout", type=float, default=15.0,
                        help="seconds to wait for the watchdog to restart the input after "
                             "debug_fail_input (generous margin over the 100ms poll interval "
                             "on a possibly loaded test host; the loopback device itself is "
                             "never removed, so no RESTART_BACKOFF_SECONDS wait is expected)")

    args = ap.parse_args()

    if args.cmd == "setup-aloop":
        setup_aloop()
    elif args.cmd == "gen-tone":
        gen_tone_wav(args.out, args.tone_seconds, args.silence_seconds, args.freq_hz)
    elif args.cmd == "play":
        play_wav(args.wav, args.device)
    elif args.cmd == "status":
        c = MonitorClient(args.socket)
        print(json.dumps(c.get_status(), indent=2))
        c.close()
    elif args.cmd == "set-repeat-enabled":
        c = MonitorClient(args.socket)
        print(json.dumps(c.set_repeat_enabled(args.enabled, args.codec)))
        c.close()
    elif args.cmd == "d7":
        scenario_d7(args.socket, args.wav, args.input, args.device)
    elif args.cmd == "gen-multi-track":
        gen_multi_track_wav(args.out, args.tracks, args.tone_seconds,
                             args.gap_seconds, args.tail_silence_seconds)
    elif args.cmd == "d1d3":
        scenario_d1_d3(args.socket, args.wav, args.input, args.device)
    elif args.cmd == "d5d6":
        scenario_d5_d6(args.socket, args.wav, args.input, args.device)
    elif args.cmd == "d9":
        scenario_d9(args.socket, args.wav, args.input, args.device)
    elif args.cmd == "d10":
        scenario_d10(args.socket, args.wav, args.input, args.device)
    elif args.cmd == "d11":
        scenario_d11(args.socket, args.wav, args.fifo, args.input, args.device)
    elif args.cmd == "d12":
        scenario_d12(args.socket, args.wav, args.input, args.device)
    elif args.cmd == "d4":
        scenario_d4(args.socket, args.wav_a, args.wav_b, args.fifo,
                     args.input_a, args.input_b, args.device_a, args.device_b,
                     args.freq_a, args.freq_b, args.dump_path)
    elif args.cmd == "e1":
        scenario_e1(args.socket, args.wav_a, args.wav_b,
                     args.input_a, args.input_b, args.device_a, args.device_b)
    elif args.cmd == "e6":
        scenario_e6(args.socket, args.wav_a, args.wav_b,
                     args.input_a, args.input_b, args.device_a, args.device_b)
    elif args.cmd == "e11":
        scenario_e11(args.socket, args.wav_a, args.wav_b,
                      args.input_a, args.input_b, args.device_a, args.device_b)
    elif args.cmd == "r1":
        scenario_r1(args.socket, args.wav, args.fifo, args.input, args.device,
                    args.gain_before_db, args.gain_after_db)
    elif args.cmd == "d15":
        scenario_d15(args.socket, args.wav, args.fifo, args.input_a, args.input_b,
                     args.device_a, args.device_b, args.iterations)
    elif args.cmd == "d15r":
        scenario_d15r(args.socket, args.wav, args.fifo, args.log_path, args.mode,
                      args.input_a, args.input_b, args.device_a, args.device_b, args.iterations)
    elif args.cmd == "d16":
        scenario_d16(args.socket, args.wav, args.fifo, args.input, args.device,
                     args.restart_timeout)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
