#!/usr/bin/env python3
"""fifo_reader_stub.py — paced FIFO reader for repeat-feature D-tests.

Stands in for OwnTone's pipe reader during daemon integration tests.
Opens a FIFO for reading, drains it at a
fixed real-time pace (default: 44100 Hz stereo s16le -> 176400 B/s, matching
the monitor's OUTPUT_RATE), and logs occupancy (via FIONREAD) plus running
byte counts to stdout as newline-delimited JSON, one line per poll interval.

This is a dev-only tool -- not installed, not referenced by the production
daemon or installer.

Usage:
    python3 fifo_reader_stub.py --path /run/user/1000/repeat_test.fifo \
        [--rate 176400] [--duration 60] [--log-interval 0.5]

SILENCE RULE reminder: this tool
reads a *test* FIFO created for a standalone test daemon instance -- never the
live autostream FIFO that OwnTone/AirPlay consumes.
"""

import argparse
import ctypes
import fcntl
import json
import os
import sys
import time


FIONREAD = 0x541B  # Linux ioctl to query bytes available to read


def fionread(fd: int) -> int:
    buf = ctypes.c_int(0)
    fcntl.ioctl(fd, FIONREAD, buf)
    return buf.value


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--path", required=True, help="FIFO path to read")
    ap.add_argument("--rate-bytes-per-sec", type=int, default=176400,
                     help="Pace to drain at, in bytes/sec (default: 44.1kHz stereo s16le)")
    ap.add_argument("--duration", type=float, default=0.0,
                     help="Stop after this many seconds (0 = run until Ctrl-C)")
    ap.add_argument("--log-interval", type=float, default=0.5,
                     help="Seconds between occupancy log lines")
    ap.add_argument("--chunk-ms", type=float, default=20.0,
                     help="Read chunk size in milliseconds of audio at rate-bytes-per-sec")
    ap.add_argument("--dump-path", default=None,
                     help="Also write every byte read to this raw s16le file "
                          "(truncated at start), for offline envelope/interleave analysis "
                          "of the live-interrupt crossfade (repeat_test_driver.py scenario_d4). "
                          "Omit for scenarios that only need the existing occupancy telemetry.")
    args = ap.parse_args()

    if not os.path.exists(args.path):
        print(f"error: FIFO does not exist: {args.path}", file=sys.stderr)
        return 2

    chunk_bytes = max(1, int(args.rate_bytes_per_sec * (args.chunk_ms / 1000.0)))
    chunk_period = args.chunk_ms / 1000.0

    # Open blocking for read; a FIFO read() blocks until a writer opens too,
    # matching how OwnTone's pipe input behaves (reader opens once, keeps
    # working across writer opens/closes).
    fd = os.open(args.path, os.O_RDONLY)
    dump_f = open(args.dump_path, "wb") if args.dump_path else None

    total_bytes = 0
    last_log = time.monotonic()
    start = last_log
    stalls = 0

    try:
        while True:
            loop_start = time.monotonic()

            try:
                data = os.read(fd, chunk_bytes)
            except BlockingIOError:
                data = b""

            n = len(data)
            total_bytes += n
            if dump_f is not None and n > 0:
                dump_f.write(data)
            if n == 0:
                stalls += 1

            now = time.monotonic()
            if now - last_log >= args.log_interval:
                occ = fionread(fd)
                print(json.dumps({
                    "t": round(now - start, 3),
                    "occupancy_bytes": occ,
                    "total_bytes_read": total_bytes,
                    "last_read_bytes": n,
                    "stalls": stalls,
                }), flush=True)
                last_log = now

            if args.duration > 0 and (now - start) >= args.duration:
                break

            # Pace to real time: sleep out the remainder of this chunk's
            # nominal duration so occupancy reflects a realistic consumer,
            # not a tight drain loop.
            elapsed = time.monotonic() - loop_start
            remaining = chunk_period - elapsed
            if remaining > 0:
                time.sleep(remaining)
    except KeyboardInterrupt:
        pass
    finally:
        os.close(fd)
        if dump_f is not None:
            dump_f.close()

    print(json.dumps({
        "summary": True,
        "total_bytes_read": total_bytes,
        "elapsed_s": round(time.monotonic() - start, 3),
        "stalls": stalls,
    }), flush=True)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
