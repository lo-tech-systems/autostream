#!/usr/bin/env python3
"""bench_state.py -- timings of the state store.

Publishes with a subscriber attached and reads snapshots, 100,000 times each,
and prints the median and the 99th percentile in microseconds. Then times one
coordinator cycle's worth of work together (a handful of publishes closed as
one batch) so a regression can be read against the load the appliance sees:
one cycle every half second.

    python tools/bench_state.py [iterations]
"""
from __future__ import annotations

import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "core"))

import autostream_state as state
from autostream_state import FrozenDict


def percentiles(samples: list[float]) -> tuple[float, float]:
    samples.sort()
    return samples[len(samples) // 2] * 1e6, samples[int(len(samples) * 0.99)] * 1e6


def timed(fn, n: int) -> tuple[float, float]:
    out = []
    clock = time.perf_counter
    for i in range(n):
        t0 = clock()
        fn(i)
        out.append(clock() - t0)
    return percentiles(out)


def inputs_part(i: int) -> state.InputsPart:
    level = FrozenDict({
        "index": 1, "label": "Input 1", "dbfs": -40.0 + (i % 7), "detected_hz": 48000.0,
        "vu_history": {"left": [float(j) for j in range(60)], "right": [float(j) for j in range(60)]},
    })
    entry = state.InputEntry(
        index=1, device="hw:0", input_type="line", capturing=True, replay_origin=False,
        rate_note="note", sample_rate_text="text", rate_mismatch_hz=0, level=level)
    return state.InputsPart((entry, entry), 0, "")


def hub_row(st, session, n: int, waiters: int = 8) -> tuple[float, float]:
    """Publish with notify while a stream hub is subscribed and *waiters*
    threads are parked on it, as eight open streams are."""
    from webui import stream

    hub = stream.StreamHub(st)
    hub.start()
    stop = threading.Event()

    def park() -> None:
        seen = hub.generation()
        while not stop.is_set():
            woke = hub.wait_past(seen, 1.0)
            if woke is not None:
                seen = woke

    threads = [threading.Thread(target=park, daemon=True) for _ in range(waiters)]
    for t in threads:
        t.start()
    try:
        return timed(lambda i: session.publish(state.SessionPart(bool(i & 1), "input1")).notify(), n)
    finally:
        stop.set()
        hub.stop()
        for t in threads:
            t.join(2.0)


def main() -> None:
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 100_000
    st = state.store()
    st.reset_for_tests()
    st._test_mode = False  # time the production path, not leak tracking
    seen = []
    st.subscribe(seen.append)
    session = st.claim("session", "bench")
    settings = st.claim("settings", "bench")
    inputs = st.claim("inputs", "bench")
    monitor = st.claim("monitor", "bench")
    repeat = st.claim("repeat", "bench")

    p50, p99 = timed(lambda i: session.publish(state.SessionPart(bool(i & 1), "input1")).notify(), n)
    print(f"publish+notify (digest moves): p50 {p50:.1f} us  p99 {p99:.1f} us")
    p50, p99 = timed(lambda i: settings.publish(state.SettingsPart(0)).notify(), n)
    print(f"publish+notify (digest equal): p50 {p50:.1f} us  p99 {p99:.1f} us")
    p50, p99 = timed(lambda i: st.snapshot(), n)
    print(f"snapshot():                    p50 {p50:.2f} us  p99 {p99:.2f} us")
    p50, p99 = hub_row(st, session, max(n // 10, 1000))
    print(f"publish+notify, stream hub, 8 waiters: p50 {p50:.1f} us  p99 {p99:.1f} us")

    def cycle(i: int) -> None:
        with st.batch():
            monitor.publish(state.MonitorRuntimeInfo("b", "info", True, float(i))).notify()
            repeat.publish(state.RepeatPart({"enabled": True, "recording": {"seconds": float(i)}})).notify()
            session.publish(state.SessionPart(bool(i & 1), "input1")).notify()
            inputs.publish(inputs_part(i)).notify()
            settings.update(lambda cur: state.SettingsPart(cur.generation + 1)).notify()

    p50, p99 = timed(cycle, max(n // 10, 1000))
    print(f"per tick (5 publishes, 1 batch): p50 {p50:.1f} us  p99 {p99:.1f} us")


if __name__ == "__main__":
    main()
