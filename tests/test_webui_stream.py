"""tests/test_webui_stream.py

The state change stream and the state snapshot body of webui/stream.py, on a
fresh StateStore and a real socket pair: the pure helpers, the hub, the
client cap, and the stream loop with its resume, coalescing, heartbeat,
lifetime and write-timeout behaviour.

Timing assertions are loose on purpose: they catch a stream that blocks or
never ends, not a few milliseconds.
"""
from __future__ import annotations

import json
import random
import socket
import sys
import threading
import time
from pathlib import Path

import pytest

_CORE = str(Path(__file__).resolve().parent.parent / "core")
if _CORE not in sys.path:
    sys.path.insert(0, _CORE)

from autostream_state import (
    PART_NAMES, HealthPart, Origin, OutputsPart, OutputUnitView, TrackPart)
from autostream_state.store import StateStore
from stream_helpers import Client, Publisher, wait_for
from track_id.models import disabled_snapshot
from webui import stream


# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------

class _Wfile:
    def __init__(self, sock) -> None:
        self._sock = sock

    def write(self, data: bytes) -> None:
        self._sock.sendall(data)

    def flush(self) -> None:
        pass


class FakeHandler:
    """The parts of a request handler the stream uses, over a socket."""

    def __init__(self, sock, headers=None, path: str = "/api/v1/events") -> None:
        self.connection = sock
        self.wfile = _Wfile(sock)
        self.headers = dict(headers or {})
        self.path = path
        self.close_connection = False
        self._head: list = []

    def send_response(self, code: int, message=None) -> None:
        self._head = [f"HTTP/1.1 {code} X\r\n".encode()]

    def send_header(self, name: str, value: str) -> None:
        self._head.append(f"{name}: {value}\r\n".encode())

    def end_headers(self) -> None:
        self.wfile.write(b"".join(self._head) + b"\r\n")


class Running:
    """A stream running on its own thread, and the client reading it."""

    def __init__(self, hub, headers=None, path="/api/v1/events", via="serve") -> None:
        self.server_sock, client_sock = socket.socketpair()
        self.client = Client(client_sock)
        self.reason = None
        self.started = time.monotonic()
        self.ended = None
        self.handler = FakeHandler(self.server_sock, headers, path)
        self.thread = threading.Thread(target=self._run, args=(hub, via), daemon=True)
        self.thread.start()

    def _run(self, hub, via) -> None:
        try:
            if via == "serve":
                self.reason = stream.serve_events(self.handler, hub)
            else:
                stream.send_events(self.handler, None)
        finally:
            self.ended = time.monotonic()
            try:
                self.server_sock.close()
            except OSError:
                pass

    def finished(self) -> bool:
        return not self.thread.is_alive()

    def close(self) -> None:
        try:
            self.client.sock.close()
        except OSError:
            pass


@pytest.fixture
def store():
    return StateStore()


@pytest.fixture
def pub(store):
    return Publisher(store)


@pytest.fixture
def hub(store):
    h = stream.StreamHub(store)
    h.start()
    yield h
    h.stop()


@pytest.fixture
def run(hub):
    """Start streams; at the end stop the hub and check every thread ended."""
    started: list = []

    def start(**kw):
        r = Running(hub, **kw)
        started.append(r)
        return r

    yield start
    hub.stop()
    for r in started:
        r.close()
    for r in started:
        r.thread.join(5.0)
        assert not r.thread.is_alive()


@pytest.fixture
def installed(hub):
    stream.install(hub)
    yield hub
    stream.install(None)


# -----------------------------------------------------------------------------
# 1. parse_since
# -----------------------------------------------------------------------------

_BOOT = "0123456789abcdef"


def test_parse_since_reads_the_header_before_the_query():
    got = stream.parse_since(f"{_BOOT}-12", f"since={_BOOT}-99")
    assert got == stream.Since(_BOOT, 12)


def test_parse_since_reads_the_query_alone():
    assert stream.parse_since(None, f"x=1&since={_BOOT}-7") == stream.Since(_BOOT, 7)
    assert stream.parse_since("", f"since={_BOOT}-7") == stream.Since(_BOOT, 7)


def test_parse_since_with_neither_is_none():
    assert stream.parse_since(None, "") is None
    assert stream.parse_since(None, "other=1") is None


@pytest.mark.parametrize("bad", [
    "", "abc", "1234", _BOOT.upper() + "-1", "0123456789abcde-1", f"{_BOOT}--1",
    f"{_BOOT}-" + "1" * 19, f"{_BOOT}-12x", f"{_BOOT}-12\n", f"{_BOOT}-",
])
def test_parse_since_refuses_a_malformed_id(bad):
    assert stream.parse_since(bad, "") is None
    assert stream.parse_since(None, "since=" + bad) is None


# -----------------------------------------------------------------------------
# 2. changed_parts
# -----------------------------------------------------------------------------

def _scripted(store, pub):
    """Three parts moved at known versions; returns the snapshot."""
    pub("settings")     # version 1
    pub("session")      # 2
    pub("settings")     # 3
    pub("outputs")      # 4
    return store.snapshot()


def test_changed_parts_gives_everything_to_a_client_with_no_position(store, pub):
    snap = _scripted(store, pub)
    assert stream.changed_parts(snap, None) == (tuple(PART_NAMES), True)


def test_changed_parts_gives_everything_after_a_restart(store, pub):
    snap = _scripted(store, pub)
    other = stream.Since("f" * 16, 2)
    assert stream.changed_parts(snap, other) == (tuple(PART_NAMES), True)


def test_changed_parts_gives_everything_to_an_id_ahead_of_the_store(store, pub):
    snap = _scripted(store, pub)
    ahead = stream.Since(snap.boot, snap.version + 5)
    assert stream.changed_parts(snap, ahead) == (tuple(PART_NAMES), True)


def test_changed_parts_gives_nothing_to_a_current_client(store, pub):
    snap = _scripted(store, pub)
    assert stream.changed_parts(snap, stream.Since(snap.boot, snap.version)) == ((), False)


def test_changed_parts_names_the_parts_moved_since_the_clients_version(store, pub):
    snap = _scripted(store, pub)
    got = stream.changed_parts(snap, stream.Since(snap.boot, 2))
    assert got == (("settings", "outputs"), False)
    got = stream.changed_parts(snap, stream.Since(snap.boot, 3))
    assert got == (("outputs",), False)
    got = stream.changed_parts(snap, stream.Since(snap.boot, 0))
    assert got == (("session", "settings", "outputs"), False)


# -----------------------------------------------------------------------------
# 3. event_bytes
# -----------------------------------------------------------------------------

def test_event_bytes_is_one_compact_ascii_event(store, pub):
    snap = _scripted(store, pub)
    raw = stream.event_bytes(snap, ("session", "outputs"), False)
    raw.decode("ascii")
    assert raw.endswith(b"\n\n")
    lines = raw.decode().split("\n")
    assert lines[0] == f"id: {snap.boot}-{snap.version}"
    assert lines[1] == "event: change"
    assert lines[2] == (
        'data: {"boot":"%s","version":%d,"parts":["session","outputs"],"resync":false}'
        % (snap.boot, snap.version))
    assert lines[3:] == ["", ""]
    assert stream.event_id(snap) == f"{snap.boot}-{snap.version}"


def test_event_bytes_marks_a_resync(store):
    raw = stream.event_bytes(store.snapshot(), tuple(PART_NAMES), True)
    data = json.loads(raw.decode().split("data: ")[1])
    assert data["resync"] is True
    assert data["parts"] == list(PART_NAMES)


# -----------------------------------------------------------------------------
# 4. The hub
# -----------------------------------------------------------------------------

def test_a_change_with_no_parts_does_not_step_the_generation(store, pub, hub):
    pub("settings")
    base = hub.generation()
    assert base == 1
    # A tag-only change: nothing moved, a tag was given.
    store.claim("settings", "test_owner").publish(store.snapshot().settings, tags=("x",)).notify()
    # An empty batch close.
    store.batch().close()
    assert hub.generation() == base


def test_a_change_with_parts_steps_the_generation_once(pub, hub):
    pub("settings")
    assert hub.generation() == 1
    pub("session")
    assert hub.generation() == 2


def test_a_batch_of_publishes_steps_the_generation_once(store, pub, hub):
    with store.batch():
        for part in ("settings", "session", "settings", "outputs", "repeat"):
            pub(part)
        assert hub.generation() == 0
    assert hub.generation() == 1


def test_wait_past_returns_at_once_when_already_past(pub, hub):
    pub("settings")
    t0 = time.monotonic()
    assert hub.wait_past(0, 5.0) == 1
    assert time.monotonic() - t0 < 1.0


def test_wait_past_returns_the_new_generation_on_a_change(pub, hub):
    got = []
    t = threading.Thread(target=lambda: got.append(hub.wait_past(0, 5.0)), daemon=True)
    t.start()
    time.sleep(0.05)
    pub("settings")
    t.join(3.0)
    assert got == [1]


def test_wait_past_returns_none_on_timeout(hub):
    assert hub.wait_past(0, 0.05) is None


def test_stop_releases_every_waiter_and_unsubscribes(store, pub, hub):
    results = []
    threads = [threading.Thread(target=lambda: results.append(hub.wait_past(0, 30.0)), daemon=True)
               for _ in range(8)]
    for t in threads:
        t.start()
    time.sleep(0.1)
    t0 = time.monotonic()
    hub.stop()
    for t in threads:
        t.join(3.0)
    assert time.monotonic() - t0 < 2.0
    assert results == [None] * 8
    assert hub.stopping
    pub("settings")
    assert hub.generation() == 0


def test_start_is_idempotent(store, hub):
    hub.start()
    hub.start()
    assert len(store._subs) == 1


def test_a_stopped_hub_can_start_again(pub, hub):
    hub.stop()
    hub.start()
    assert not hub.stopping
    pub("settings")
    assert hub.generation() == 1


# -----------------------------------------------------------------------------
# 5. The subscriber never waits on a client
# -----------------------------------------------------------------------------

def test_publishing_is_not_slowed_by_parked_waiters_or_a_stalled_stream(
        monkeypatch, store, pub, hub, run):
    monkeypatch.setattr(stream, "WRITE_TIMEOUT_S", 20.0)
    real = stream.event_bytes
    # One enormous event: the single write blocks on a peer that never reads.
    monkeypatch.setattr(stream, "event_bytes",
                        lambda *a: b": " + b"x" * (4 << 20) + b"\n\n" + real(*a))
    stalled = run()
    time.sleep(0.1)                 # its first write is now blocked; the client never reads
    stop = threading.Event()

    def parked():
        gen = 0
        while not stop.is_set():
            gen = hub.wait_past(gen, 0.5) or gen

    waiters = [threading.Thread(target=parked, daemon=True) for _ in range(8)]
    for t in waiters:
        t.start()
    time.sleep(0.1)
    lags = []
    for i in range(1000):
        part = ("settings", "session")[i % 2]
        pending = pub.bump(part)
        t0 = time.perf_counter()
        pending.notify()
        lags.append(time.perf_counter() - t0)
    assert not stalled.finished()
    stop.set()
    lags.sort()
    assert lags[int(len(lags) * 0.99)] < 0.005
    assert lags[-1] < 0.1
    for t in waiters:
        t.join(3.0)
    assert hub.client_count() == 0


# -----------------------------------------------------------------------------
# 6. The cap
# -----------------------------------------------------------------------------

def test_the_cap_admits_eight_and_refuses_the_ninth(hub):
    assert [hub.enter() for _ in range(stream.MAX_CLIENTS)] == [True] * 8
    assert hub.client_count() == 8
    assert hub.enter() is False
    assert hub.client_count() == 8
    hub.exit()
    assert hub.client_count() == 7
    assert hub.enter() is True
    assert hub.client_count() == 8


# -----------------------------------------------------------------------------
# 7. The stream over a socket pair
# -----------------------------------------------------------------------------

def test_a_new_client_gets_the_retry_and_a_resync_event(store, pub, run):
    pub("settings")
    r = run()
    assert r.client.pull_until(b"event: change")
    head = r.client.buf.split(b"\r\n\r\n")[0].decode()
    assert head.startswith("HTTP/1.1 200")
    assert "Content-Type: text/event-stream" in head
    assert "Cache-Control: no-store" in head
    assert "X-Accel-Buffering: no" in head
    assert "X-Content-Type-Options: nosniff" in head
    assert r.client.body.startswith(b"retry: 2000\n\n")
    (event,) = r.client.events()
    assert event["resync"] is True
    assert event["parts"] == list(PART_NAMES)
    assert event["version"] == store.snapshot().version
    assert event["id"] == f"{store.snapshot().boot}-{store.snapshot().version}"
    assert r.handler.close_connection is True


def test_a_current_client_hears_nothing_until_the_heartbeat_then_the_next_change(
        monkeypatch, store, pub, run):
    monkeypatch.setattr(stream, "HEARTBEAT_S", 0.4)
    monkeypatch.setattr(stream, "LIVENESS_S", 0.1)
    pub("settings")
    snap = store.snapshot()
    r = run(headers={"Last-Event-ID": f"{snap.boot}-{snap.version}"})
    assert r.client.pull_until(b"retry: 2000\n\n")
    r.client.pull(0.15)
    assert r.client.body == b"retry: 2000\n\n"
    assert r.client.pull_until(b": ka\n\n")
    pub("session")
    assert r.client.pull_until(b"event: change")
    (event,) = r.client.events()
    assert event["parts"] == ["session"]
    assert event["resync"] is False


def test_an_older_id_gets_one_event_with_the_parts_moved_since(store, pub, run):
    pub("settings")
    old = store.snapshot()
    pub("session")
    pub("outputs")
    r = run(headers={"Last-Event-ID": f"{old.boot}-{old.version}"})
    assert r.client.pull_until(b"event: change")
    (event,) = r.client.events()
    assert event["parts"] == ["session", "outputs"]
    assert event["resync"] is False


def test_the_query_resumes_when_there_is_no_header(store, pub, run):
    pub("settings")
    old = store.snapshot()
    pub("session")
    r = run(path=f"/api/v1/events?since={old.boot}-{old.version}")
    assert r.client.pull_until(b"event: change")
    assert r.client.events()[0]["parts"] == ["session"]


def test_publishes_within_the_window_become_one_event(store, pub, run):
    snap = store.snapshot()
    r = run(headers={"Last-Event-ID": f"{snap.boot}-{snap.version}"})
    assert r.client.pull_until(b"retry: 2000")
    for part in ("settings", "session", "settings", "session", "settings"):
        pub(part)
        time.sleep(0.01)
    assert r.client.pull_until(b"event: change")
    r.client.pull(0.5)
    (event,) = r.client.events()
    assert event["parts"] == ["session", "settings"]
    assert event["version"] == store.snapshot().version


def test_a_change_made_while_another_threads_batch_is_open_is_not_lost_or_repeated(
        store, pub, run):
    snap = store.snapshot()
    r = run(headers={"Last-Event-ID": f"{snap.boot}-{snap.version}"})
    assert r.client.pull_until(b"retry: 2000")
    opened, close = threading.Event(), threading.Event()

    def other_thread():
        with store.batch():
            pub("session")          # held until the batch closes
            opened.set()
            close.wait(5.0)

    t = threading.Thread(target=other_thread, daemon=True)
    t.start()
    assert opened.wait(3.0)
    pub("settings")                 # wakes the stream; the snapshot already holds both
    assert r.client.pull_until(b"event: change")
    (early,) = r.client.events()
    assert early["parts"] == ["session", "settings"]
    close.set()                     # the batch's own change arrives now
    t.join(3.0)
    r.client.pull(0.8)
    assert len(r.client.events()) == 1


def test_a_peer_that_closes_is_noticed_without_a_write(monkeypatch, hub, installed):
    monkeypatch.setattr(stream, "LIVENESS_S", 0.1)
    server, client = socket.socketpair()
    handler = FakeHandler(server)
    reasons = []
    t = threading.Thread(
        target=lambda: reasons.append(stream.serve_events(handler, hub)), daemon=True)
    hub.enter()
    t.start()
    c = Client(client)
    assert c.pull_until(b"retry: 2000")
    client.close()
    t.join(3.0)
    hub.exit()
    assert not t.is_alive()
    assert reasons == ["ConnectionResetError"]
    server.close()


def test_a_closed_peer_frees_its_slot(monkeypatch, hub, installed, run):
    monkeypatch.setattr(stream, "LIVENESS_S", 0.1)
    r = run(via="send")
    assert wait_for(lambda: hub.client_count() == 1)
    r.close()
    assert wait_for(lambda: hub.client_count() == 0)
    assert wait_for(r.finished)


def test_a_quiet_peer_is_not_mistaken_for_a_closed_one(monkeypatch, store, run):
    monkeypatch.setattr(stream, "LIVENESS_S", 0.05)
    snap = store.snapshot()
    r = run(headers={"Last-Event-ID": f"{snap.boot}-{snap.version}"})
    r.client.pull(0.5)
    assert not r.finished()
    assert r.reason is None


def test_a_quiet_stream_ends_at_its_lifetime_and_resumes_without_a_resync(
        monkeypatch, store, pub, run):
    monkeypatch.setattr(stream, "MAX_AGE_S", 0.5)
    monkeypatch.setattr(stream, "LIVENESS_S", 0.1)
    pub("settings")
    r = run()
    assert wait_for(r.finished, 5.0)
    assert r.reason == "lifetime"
    assert 0.35 <= r.ended - r.started <= 0.55 + 0.1 + 1.0
    r.client.pull(0.1)
    (first,) = r.client.events()
    again = run(headers={"Last-Event-ID": first["id"]})
    again.client.pull(0.2)
    assert again.client.body.startswith(b"retry: 2000")
    assert again.client.events() == []


def test_a_busy_stream_ends_at_its_lifetime_and_loses_nothing_at_the_cut(
        monkeypatch, store, pub, run):
    monkeypatch.setattr(stream, "MAX_AGE_S", 0.5)
    monkeypatch.setattr(stream, "LIVENESS_S", 0.1)
    stop = threading.Event()
    seq = []

    def busy():
        i = 0
        while not stop.is_set():
            part = ("settings", "session")[i % 2]
            i += 1
            pub(part)
            seq.append(part)
            time.sleep(0.1)

    snap = store.snapshot()
    pub("outputs")
    r = run(headers={"Last-Event-ID": f"{snap.boot}-{store.snapshot().version}"})
    t = threading.Thread(target=busy, daemon=True)
    t.start()
    try:
        assert wait_for(r.finished, 5.0)
        assert r.reason == "lifetime"
        assert r.ended - r.started < 0.55 + stream.COALESCE_S + 1.0
    finally:
        stop.set()
        t.join(3.0)
    r.client.pull(0.1)
    events = r.client.events()
    last = events[-1] if events else None
    since = (stream.Since(last["boot"], last["version"]) if last
             else stream.Since(snap.boot, store.snapshot().version))
    resumed = run(headers={"Last-Event-ID": f"{since.boot}-{since.version}"})
    resumed.client.pull(0.3)
    final = store.snapshot()
    expected = [p for p in PART_NAMES if final.part_versions.get(p, 0) > since.version]
    got = resumed.client.events()
    if expected:
        assert [e["parts"] for e in got] == [expected]
        assert got[0]["resync"] is False
    else:
        assert got == []
    told = set()
    for e in events + got:
        told.update(e["parts"])
    assert {"settings", "session"} <= told


def test_each_stream_draws_its_own_lifetime_between_nine_tenths_and_eleven_tenths(
        monkeypatch, hub):
    factors = []
    source = random.Random(7)

    class Spy:
        @staticmethod
        def uniform(a, b):
            value = source.uniform(a, b)
            factors.append(value)
            return value

    monkeypatch.setattr(stream, "random", Spy)
    runs = [Running(hub) for _ in range(50)]
    try:
        assert wait_for(lambda: len(factors) == 50, 10.0)
    finally:
        hub.stop()
        for r in runs:
            r.close()
        for r in runs:
            r.thread.join(5.0)
    assert all(0.9 <= f <= 1.1 for f in factors)
    assert len(set(factors)) == 50
    assert max(factors) - min(factors) > 0.15


def test_a_peer_that_never_reads_is_dropped_by_the_write_timeout(
        monkeypatch, store, pub, hub, installed):
    monkeypatch.setattr(stream, "WRITE_TIMEOUT_S", 0.3)
    real = stream.event_bytes
    # Each event carries a 16 KB comment so the kernel buffers really fill.
    monkeypatch.setattr(stream, "event_bytes",
                        lambda *a: b": " + b"x" * 16384 + b"\n\n" + real(*a))
    server, client = socket.socketpair()
    try:
        client.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2048)
    except OSError:
        pass
    handler = FakeHandler(server)
    hub.enter()
    reasons = []
    t = threading.Thread(
        target=lambda: reasons.append(stream.serve_events(handler, hub)), daemon=True)
    t.start()
    deadline = time.monotonic() + 5.0
    i = 0
    while t.is_alive() and time.monotonic() < deadline:
        pub(("settings", "session")[i % 2])
        i += 1
        time.sleep(0.05)
    t.join(1.0)
    hub.exit()
    client.close()
    server.close()
    assert not t.is_alive()
    assert reasons == ["timeout"]
    assert hub.client_count() == 0


def test_a_matching_origin_is_served(hub, installed, run):
    r = run(headers={"Origin": "http://app.local:8080", "Host": "app.local:8080"}, via="send")
    assert r.client.pull_until(b"retry: 2000")
    assert hub.client_count() == 1


def test_a_request_with_no_origin_is_served(hub, installed, run):
    r = run(headers={"Host": "app.local"}, via="send")
    assert r.client.pull_until(b"retry: 2000")
    assert hub.client_count() == 1


def test_an_origin_naming_another_host_is_refused_and_takes_no_slot(hub, installed, run):
    r = run(headers={"Origin": "http://elsewhere.example", "Host": "app.local"}, via="send")
    assert wait_for(r.finished)
    r.client.pull(0.2)
    assert r.client.buf.startswith(b"HTTP/1.1 403")
    assert b"cross_origin" in r.client.body
    assert hub.client_count() == 0


def test_the_ninth_client_is_refused_with_the_tunnelled_503(hub, installed, run):
    for _ in range(stream.MAX_CLIENTS):
        assert hub.enter()
    r = run(via="send")
    assert wait_for(r.finished)
    r.client.pull(0.2)
    assert r.client.buf.startswith(b"HTTP/1.1 200")
    assert json.loads(r.client.body) == {
        "ok": False, "error": "too_many_clients", "error_status": 503, "retryable": True}
    assert hub.client_count() == stream.MAX_CLIENTS


def test_without_a_hub_the_events_route_answers_not_found(run):
    server, client = socket.socketpair()
    stream.install(None)
    stream.send_events(FakeHandler(server), None)
    c = Client(client)
    c.pull(0.2)
    assert json.loads(c.body)["error"] == "not_found"
    server.close()
    client.close()


# -----------------------------------------------------------------------------
# 8. state_json
# -----------------------------------------------------------------------------

def test_state_json_carries_every_part_as_plain_json(store):
    owner = "test_owner"
    store.claim("track", owner).publish(
        TrackPart(entries={0: disabled_snapshot()}, service_enabled=True)).notify()
    unit = OutputUnitView(
        id="a", name="Speaker A", selected=True, volume=30, muted=False,
        availability="ok", cause=Origin.USER, reported=None)
    store.claim("outputs", owner).publish(OutputsPart(units=(unit,), connected=True)).notify()
    store.claim("health", owner).publish(
        HealthPart(watchdog_last_restart_at=float("-inf"))).notify()
    snap = store.snapshot()

    body = stream.state_json(snap, clients=3)
    text = json.dumps(body, allow_nan=False)
    assert body["boot"] == snap.boot
    assert body["version"] == snap.version
    assert body["clients"] == 3
    assert set(body["parts"]) == set(PART_NAMES)
    assert set(body["part_versions"]) <= set(PART_NAMES)
    assert list(body["parts"]["track"]["entries"]) == ["0"]
    assert body["parts"]["outputs"]["units"][0]["cause"] == "user"
    assert body["parts"]["health"]["watchdog_last_restart_at"] is None
    assert json.loads(text) == body


# -----------------------------------------------------------------------------
# 9. state_body
# -----------------------------------------------------------------------------

def test_the_state_body_is_built_once_per_version(monkeypatch, pub, hub):
    builds = []
    real = stream.state_json
    monkeypatch.setattr(stream, "state_json",
                        lambda snap, *, clients: builds.append(snap.version) or real(snap, clients=clients))
    pub("settings")
    first = hub.state_body()
    assert hub.state_body() is first
    assert builds == [1]
    pub("session")
    second = hub.state_body()
    assert second is not first
    assert builds == [1, 2]
    assert json.loads(second)["version"] == 2


def test_the_state_body_is_rebuilt_after_its_age_under_the_same_version(monkeypatch, store, pub):
    now = [100.0]
    hub = stream.StreamHub(store, clock=lambda: now[0])
    builds = []
    real = stream.state_json
    monkeypatch.setattr(stream, "state_json",
                        lambda snap, *, clients: builds.append(snap.version) or real(snap, clients=clients))
    pub("settings")
    hub.state_body()
    now[0] += stream.BODY_MAX_AGE_S * 0.5
    hub.state_body()
    assert builds == [1]
    now[0] += stream.BODY_MAX_AGE_S
    hub.state_body()
    assert builds == [1, 1]


def test_the_state_body_reports_the_current_client_count(pub, hub):
    pub("settings")
    assert json.loads(hub.state_body())["clients"] == 0
    hub.enter()
    assert json.loads(hub.state_body())["clients"] == 1


def test_concurrent_callers_of_an_old_body_share_one_build(monkeypatch, store, pub):
    now = [100.0]
    hub = stream.StreamHub(store, clock=lambda: now[0])
    pub("settings")
    hub.state_body()
    now[0] += 10.0
    builds = []
    real = stream.state_json

    def slow(snap, *, clients):
        builds.append(1)
        time.sleep(0.2)
        return real(snap, clients=clients)

    monkeypatch.setattr(stream, "state_json", slow)
    bodies = []
    gate = threading.Barrier(8)

    def call():
        gate.wait()
        bodies.append(hub.state_body())

    threads = [threading.Thread(target=call, daemon=True) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(5.0)
    assert len(builds) == 1
    assert len(bodies) == 8
    assert len({id(b) for b in bodies}) == 1
