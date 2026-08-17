"""autostream_align_tone.py — one-shot calibration tone writer for automatic
output alignment.

Copyright (c) 2026 Lo-tech Systems Limited. All rights reserved.

Writes a periodic calibration tone into the PCM FIFO that feeds owntone, so
an external measurement can determine the alignment offset of the output
this appliance drives. Run standalone:

    python3 autostream_align_tone.py --fifo /path/to/pcm.fifo \\
        --freq-file /path/to/freq.txt

The player at the far end suspends and flushes ALL outputs if its read
deficit exceeds roughly 1500ms, so this writer supplies PCM continuously --
silence between tone bursts is written explicitly, never omitted. The loop
has no clock of its own: the pipe buffer is enlarged to hold over a second
of audio and blocking writes pace the loop, so the consumer always holds a
full lead and scheduling jitter on either side cannot starve it. The
stream timeline is sample-exact by construction.

Public interface (used directly by tests, no FIFO or real clock required):
    read_freq(path)                 -- frequency-file parser
    ms_to_frames(ms, rate)          -- duration -> frame count
    build_tone_burst(...)           -- one cached burst waveform
    build_silence(frames, channels) -- one cached silence waveform
    BurstCache                      -- per-frequency/per-length waveform cache
    build_period_frames(...)        -- one period's samples (cache-backed)
    plan_chunks(total_frames, chunk_frames) -- write-pacing chunk sizes
    sleep_until(deadline, clock, sleep) -- injectable-clock pacer primitive
    open_fifo_for_write(path, ...)  -- nonblocking-open-then-blocking-write helper
    main(argv)                      -- CLI entry point
"""
from __future__ import annotations

import argparse
import array
import errno
import math
import os
import signal
import sys
import time
from typing import Callable, Dict, List, Optional

# The pipe consumer accepts signed little-endian PCM at 16 or 32 bits per
# sample; the width must match its configuration exactly or it reads the
# stream at the wrong frame rate.
SUPPORTED_BITS = (16, 32)


def _typecode(bits: int) -> str:
    return "h" if bits == 16 else "i"  # array typecodes: 2-byte / 4-byte signed


def _sample_peak(bits: int) -> float:
    return float((1 << (bits - 1)) - 1)
CHUNK_MS = 50
RAMP_MS_DEFAULT = 10
OPEN_NONBLOCK_TIMEOUT_S = 15.0
# ~0.7s of 48k/32-bit stereo. The write loop has no clock of its own: it
# fills the pipe and lets blocking writes pace it, so this is the lead the
# consumer holds against scheduling jitter. Frequency changes take effect
# roughly this far behind the freq-file write, which the measurement
# design's guard bands absorb.
PIPE_BUFFER_BYTES = 256 * 1024
# How far ahead of realtime the paced writer runs: the first LEAD_S of audio
# goes out immediately, then the absolute schedule holds this lead steady.
LEAD_S = 0.6
OPEN_RETRY_SLEEP_S = 0.2
FINAL_SILENCE_MS = 50


def read_freq(path: str) -> Optional[int]:
    """Parse the frequency file: missing, empty, unparsable, or non-positive
    values all mean "silence this period" (None); a positive integer Hz
    means "burst this period"."""
    try:
        with open(path, "r") as f:
            text = f.read().strip()
    except OSError:
        return None
    if not text:
        return None
    try:
        value = int(text)
    except ValueError:
        return None
    return value if value > 0 else None


def ms_to_frames(ms: float, rate: int) -> int:
    return int(round(rate * ms / 1000.0))


def build_tone_burst(
    freq_hz: int,
    rate: int,
    channels: int,
    burst_ms: float,
    amplitude: float,
    ramp_ms: float = RAMP_MS_DEFAULT,
    bits: int = 16,
) -> "array.array[int]":
    """Interleaved signed-PCM sine burst with raised-cosine ramps on both
    ends (click suppression). Same signal is duplicated to every channel."""
    n = ms_to_frames(burst_ms, rate)
    if n <= 0:
        return array.array(_typecode(bits))
    ramp_n = min(ms_to_frames(ramp_ms, rate), n // 2)
    peak = amplitude * _sample_peak(bits)
    out = array.array(_typecode(bits), bytes((bits // 8) * channels * n))
    for i in range(n):
        gain = 1.0
        if ramp_n:
            if i < ramp_n:
                gain = 0.5 * (1.0 - math.cos(math.pi * i / ramp_n))
            elif i >= n - ramp_n:
                gain = 0.5 * (1.0 - math.cos(math.pi * (n - 1 - i) / ramp_n))
        sample = int(round(math.sin(2.0 * math.pi * freq_hz * i / rate) * gain * peak))
        base = i * channels
        for ch in range(channels):
            out[base + ch] = sample
    return out


def build_silence(frames: int, channels: int, bits: int = 16) -> "array.array[int]":
    if frames <= 0:
        return array.array(_typecode(bits))
    return array.array(_typecode(bits), bytes((bits // 8) * channels * frames))


class BurstCache:
    """Pre-computes and caches waveforms so the steady write loop only ever
    slices/concatenates buffers -- no per-sample math once warmed up."""

    def __init__(self, rate: int, channels: int, burst_ms: float, amplitude: float,
                 ramp_ms: float = RAMP_MS_DEFAULT, bits: int = 16) -> None:
        self.rate = rate
        self.channels = channels
        self.burst_ms = burst_ms
        self.amplitude = amplitude
        self.ramp_ms = ramp_ms
        self.bits = bits
        self._bursts: Dict[int, "array.array[int]"] = {}
        self._silence: Dict[int, "array.array[int]"] = {}

    def burst(self, freq_hz: int) -> "array.array[int]":
        buf = self._bursts.get(freq_hz)
        if buf is None:
            buf = build_tone_burst(
                freq_hz, self.rate, self.channels, self.burst_ms, self.amplitude, self.ramp_ms, self.bits,
            )
            self._bursts[freq_hz] = buf
        return buf

    def silence(self, frames: int) -> "array.array[int]":
        buf = self._silence.get(frames)
        if buf is None:
            buf = build_silence(frames, self.channels, self.bits)
            self._silence[frames] = buf
        return buf


def build_period_frames(freq_hz: Optional[int], cache: BurstCache, total_frames: int) -> "array.array[int]":
    """One period's worth of interleaved samples: burst-then-silence if
    freq_hz is set, otherwise silence throughout."""
    if freq_hz:
        burst = cache.burst(freq_hz)
        burst_frames = len(burst) // cache.channels
        silence_frames = max(0, total_frames - burst_frames)
        return burst + cache.silence(silence_frames)
    return cache.silence(total_frames)


def plan_chunks(total_frames: int, chunk_frames: int) -> List[int]:
    """Frame counts for successive writes covering one period, each ~chunk_frames
    (the last one shorter if total_frames isn't a multiple); sums to total_frames
    exactly."""
    if chunk_frames <= 0 or total_frames <= 0:
        return [total_frames] if total_frames > 0 else []
    n_full = total_frames // chunk_frames
    remainder = total_frames - n_full * chunk_frames
    chunks = [chunk_frames] * n_full
    if remainder:
        chunks.append(remainder)
    return chunks


def sleep_until(
    deadline: float,
    clock: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
) -> None:
    remaining = deadline - clock()
    if remaining > 0:
        sleep(remaining)


def open_fifo_for_write(
    path: str,
    timeout_s: float = OPEN_NONBLOCK_TIMEOUT_S,
    retry_sleep_s: float = OPEN_RETRY_SLEEP_S,
):
    """Open the FIFO write end without hanging forever waiting for a reader:
    poll with O_NONBLOCK until one attaches (or timeout_s elapses), then
    switch the fd to blocking so backpressure paces us for real."""
    deadline = time.monotonic() + timeout_s
    fd = None
    last_err: Optional[OSError] = None
    while time.monotonic() < deadline:
        try:
            fd = os.open(path, os.O_WRONLY | os.O_NONBLOCK)
            break
        except OSError as e:
            last_err = e
            if e.errno in (errno.ENXIO, errno.ENOENT):
                time.sleep(retry_sleep_s)
                continue
            raise
    if fd is None:
        raise TimeoutError(
            f"no reader attached to fifo {path} after {timeout_s:.0f}s ({last_err})"
        )
    os.set_blocking(fd, True)
    # Grow the pipe buffer so the consumer holds over a second of audio in
    # hand: writes run ahead until the kernel throttles them, which makes
    # the feed immune to scheduling jitter on either side of the pipe (the
    # constrained boards this runs on stall both processes routinely).
    # Best-effort: a denied or unsupported resize just keeps the default.
    try:
        import fcntl
        F_SETPIPE_SZ = getattr(fcntl, "F_SETPIPE_SZ", 1031)
        fcntl.fcntl(fd, F_SETPIPE_SZ, PIPE_BUFFER_BYTES)
    except Exception:
        pass
    return os.fdopen(fd, "wb", buffering=0)


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Write a calibration tone pattern into a PCM FIFO.")
    parser.add_argument("--fifo", required=True, help="path to the PCM FIFO to write into")
    parser.add_argument("--rate", type=int, default=44100)
    parser.add_argument("--bits", type=int, default=16, help="PCM sample width; 16 or 32")
    parser.add_argument("--channels", type=int, default=2)
    parser.add_argument("--period-ms", type=float, default=5000)
    parser.add_argument("--burst-ms", type=float, default=150)
    parser.add_argument("--freq-file", required=True, help="text file containing the burst frequency in Hz")
    parser.add_argument("--max-seconds", type=float, default=600)
    parser.add_argument("--amplitude", type=float, default=0.4, help="linear amplitude, 0..1")
    args = parser.parse_args(argv)

    if args.bits not in SUPPORTED_BITS:
        parser.error("--bits: only 16- or 32-bit PCM is supported")
    if not (0.0 < args.amplitude <= 1.0):
        parser.error("--amplitude must be > 0 and <= 1")
    if args.rate <= 0 or args.channels <= 0:
        parser.error("--rate and --channels must be positive")
    return args


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)

    stop_requested = {"stop": False}

    def _handle_signal(signum, frame) -> None:
        stop_requested["stop"] = True

    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)

    try:
        writer = open_fifo_for_write(args.fifo)
    except (OSError, TimeoutError) as e:
        print(f"event=error detail={e}", file=sys.stderr)
        return 1

    cache = BurstCache(rate=args.rate, channels=args.channels, burst_ms=args.burst_ms, amplitude=args.amplitude, bits=args.bits)
    chunk_frames = ms_to_frames(CHUNK_MS, args.rate)
    period_frames = ms_to_frames(args.period_ms, args.rate)
    chunk_plan = plan_chunks(period_frames, chunk_frames)

    run_deadline = time.monotonic() + args.max_seconds
    print(
        f"event=started fifo={args.fifo} rate={args.rate} channels={args.channels} "
        f"period_ms={args.period_ms:g} burst_ms={args.burst_ms:g}"
    )

    last_freq: object = "__unset__"
    t0 = time.monotonic()
    total_frames_written = 0
    try:
        while not stop_requested["stop"] and time.monotonic() < run_deadline:
            freq = read_freq(args.freq_file)
            if freq != last_freq:
                print(f"event=frequency value={freq or 0}")
                last_freq = freq
            period_buf = build_period_frames(freq, cache, period_frames)
            cum_frames = 0
            # Paced writes with a bounded lead: each chunk is due LEAD_S
            # ahead of its realtime position (absolute schedule anchored at
            # t0, so jitter never accumulates into drift). The consumer's
            # input loop has no throttle of its own - it reads whatever is
            # offered, so supply must approximate realtime - while the lead
            # plus the enlarged pipe buffer absorb scheduling stalls on
            # either side.
            for frames in chunk_plan:
                if stop_requested["stop"]:
                    break
                sleep_until(t0 + total_frames_written / args.rate - LEAD_S)
                start_i = cum_frames * args.channels
                end_i = (cum_frames + frames) * args.channels
                writer.write(period_buf[start_i:end_i].tobytes())
                cum_frames += frames
                total_frames_written += frames
    finally:
        print("event=stopping")
        try:
            tail = cache.silence(ms_to_frames(FINAL_SILENCE_MS, args.rate))
            writer.write(tail.tobytes())
        except Exception:
            pass
        try:
            writer.close()
        except Exception:
            pass

    return 0


if __name__ == "__main__":
    sys.exit(main())
