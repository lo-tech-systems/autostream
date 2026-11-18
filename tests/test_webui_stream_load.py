"""tests/test_webui_stream_load.py

The stream under load, through a real server: eight clients (seven reading
and one that stops reading), a refused ninth, a waiting client that takes the
stalled client's slot once it is dropped, and three threads publishing to the
store for ten seconds, one of them in batches.

The timing bounds on publishing are sanity bounds: they catch a subscriber
that waits on a socket (which would take the write timeout), not a few
milliseconds. Takes about twelve seconds.
"""
from __future__ import annotations

import logging
import sys
import threading
import time
from pathlib import Path

_CORE = str(Path(__file__).resolve().parent.parent / "core")
if _CORE not in sys.path:
    sys.path.insert(0, _CORE)

from stream_helpers import Publisher, RealServer, wait_for
import webui.protocol.hub as proto_hub
import webui.protocol.stream as proto_stream

PUBLISH_SECONDS = 10.0
PUBLISHES_PER_SECOND = 50


def _read_forever(client, stop: threading.Event) -> None:
    while not stop.is_set():
        client.pull(0.2)


def test_eight_clients_one_stalled_three_publishers(monkeypatch, caplog):
    caplog.set_level(logging.DEBUG)
    baseline_threads = threading.active_count()
    # Each event carries a 16 KB comment so the kernel buffers of the client
    # that never reads really fill, and a blocked write times out quickly.
    real_event_bytes = proto_stream.event_bytes
    monkeypatch.setattr(proto_stream, "event_bytes",
                        lambda *a: b": " + b"x" * 16384 + b"\n\n" + real_event_bytes(*a))
    monkeypatch.setattr(proto_stream, "WRITE_TIMEOUT_S", 0.5)
    server = RealServer(monkeypatch)
    store = server.store
    changes = []
    store.subscribe(lambda change: changes.append(1) if change.parts else None)
    stop_reading = threading.Event()
    readers: list = []
    reader_threads: list = []
    stalled = None
    waiting = {"client": None}
    try:
        stalled = server.connect(rcvbuf=2048)
        assert stalled.pull_until(b"retry: 2000")        # then never read again
        for _ in range(proto_hub.MAX_STREAMS_PER_ADDRESS - 1):
            c = server.connect()
            assert c.pull_until(b"retry: 2000")
            readers.append(c)
        assert server.hub.client_count() == proto_hub.MAX_STREAMS_PER_ADDRESS
        for c in readers:
            t = threading.Thread(target=_read_forever, args=(c, stop_reading), daemon=True)
            t.start()
            reader_threads.append(t)

        ninth = server.connect()
        assert ninth.pull_until(b"too_many_from_address")
        ninth.close()

        def wait_for_a_slot():
            # Tries again until it is let in, as the page does.
            while not stop_reading.is_set() and waiting["client"] is None:
                c = server.connect()
                c.pull(0.3)
                if b"retry: 2000" in c.buf:
                    waiting["client"] = c
                    reader = threading.Thread(
                        target=_read_forever, args=(c, stop_reading), daemon=True)
                    reader.start()
                    reader_threads.append(reader)
                    return
                c.close()
                time.sleep(0.3)

        tenth = threading.Thread(target=wait_for_a_slot, daemon=True)
        tenth.start()

        lags: list = []
        lag_lock = threading.Lock()
        published = set()
        stop_publishing = threading.Event()

        def publisher(part: str, batched: bool) -> None:
            pub = Publisher(store)
            period = 1.0 / PUBLISHES_PER_SECOND
            nxt = time.monotonic()
            while not stop_publishing.is_set():
                if batched:
                    with store.batch():
                        for _ in range(3):
                            pending = pub.bump(part)
                            t0 = time.perf_counter()
                            pending.notify()
                            dt = time.perf_counter() - t0
                            with lag_lock:
                                lags.append(dt)
                else:
                    pending = pub.bump(part)
                    t0 = time.perf_counter()
                    pending.notify()
                    dt = time.perf_counter() - t0
                    with lag_lock:
                        lags.append(dt)
                published.add(part)
                nxt += period
                time.sleep(max(0.0, nxt - time.monotonic()))

        publishers = [
            threading.Thread(target=publisher, args=(part, batched), daemon=True)
            for part, batched in (("outputs", False), ("session", False), ("repeat", True))
        ]
        for t in publishers:
            t.start()
        time.sleep(PUBLISH_SECONDS)
        stop_publishing.set()
        for t in publishers:
            t.join(5.0)

        final = store.snapshot()
        everyone = list(readers)

        def caught_up(clients) -> bool:
            for c in clients:
                events = c.events()
                if not events or events[-1]["version"] != final.version:
                    return False
            return True

        assert wait_for(lambda: waiting["client"] is not None, 5.0)
        tenth.join(2.0)
        everyone.append(waiting["client"])
        assert wait_for(lambda: caught_up(everyone), 3.0)

        for c in everyone:
            events = c.events()
            versions = [e["version"] for e in events]
            assert versions == sorted(versions)
            told = set()
            for e in events:
                told.update(e["data"])
            assert {"outputs", "session", "repeat"} <= told
            assert events[-1]["version"] == final.version

        ended = [r for r in caplog.records if "state stream: ended (timeout)" in r.getMessage()]
        assert len(ended) >= 1
        assert server.hub.client_count() == proto_hub.MAX_STREAMS_PER_ADDRESS

        lags.sort()
        assert lags[int(len(lags) * 0.99)] < 0.005
        assert lags[-1] < 0.1
        assert server.hub.generation() == len(changes)
    finally:
        stop_reading.set()
        for t in reader_threads:
            t.join(3.0)
        for c in readers:
            c.close()
        if waiting["client"] is not None:
            waiting["client"].close()
        if stalled is not None:
            stalled.close()
        server.close()
    assert wait_for(lambda: threading.active_count() <= baseline_threads, 2.0, 0.05)
