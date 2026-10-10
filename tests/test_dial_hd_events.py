"""Tests for the HD dial's change hub and event stream: the hub on its own,
then real clients on a real HdServer over 127.0.0.1 with a FakeCore."""
from __future__ import annotations

import dataclasses
import http.client
import json
import os
import socket
import sys
import threading
import time
from types import SimpleNamespace

import pytest

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "dial"))

import dial_hd_events as hde
import dial_hd_server as hds
import hd_scenarios as hs
from hd_fake_core import FakeCore
from dial_hd_events import ChangeHub, SSE_MAX_CLIENTS


def wait_until(predicate, timeout=3.0, step=0.01):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(step)
    return predicate()


@pytest.fixture
def core():
    return FakeCore(hs.SCENARIOS["playing_artwork"].snapshot)


@pytest.fixture
def hub(core):
    hub = ChangeHub(core, builder=lambda seq: json.dumps({"seq": seq}).encode())
    yield hub
    hub.stop()


# ---- the hub on its own ----------------------------------------------------


class TestChangeHub:
    def test_the_sequence_starts_at_one(self, hub):
        assert hub.seq() == 1

    def test_ten_publishes_before_the_thread_runs_are_one_step(self, hub):
        for _ in range(10):
            hub.publish()
        assert hub.seq() == 1                      # the thread has not run
        hub.start()
        assert wait_until(lambda: hub.seq() == 2)
        time.sleep(0.15)
        assert hub.seq() == 2

    def test_a_wake_without_a_publish_does_not_step(self, hub):
        hub.start()
        hub.poke()
        time.sleep(0.15)
        assert hub.seq() == 1

    def test_the_core_signal_steps_the_sequence(self, hub, core):
        hub.start()
        core.publish(polling=False)
        assert wait_until(lambda: hub.seq() == 2)
        core.publish(polling=True)
        assert wait_until(lambda: hub.seq() == 3)

    def test_stop_unsubscribes_from_the_core(self, hub, core):
        hub.start()
        assert len(core._subscribers) == 1
        hub.stop()
        assert core._subscribers == {}

    def test_publish_returns_at_once_even_while_a_state_is_being_built(self, core):
        building = threading.Event()
        release = threading.Event()

        def slow(seq):
            building.set()
            release.wait(3)
            return b"{}"

        hub = ChangeHub(core, builder=slow)
        hub.start()
        try:
            thread = threading.Thread(target=hub.state, daemon=True)
            thread.start()
            assert building.wait(2)
            started = time.monotonic()
            for _ in range(100):
                hub.publish()
            assert time.monotonic() - started < 0.05
        finally:
            release.set()
            hub.stop()

    def test_wait_for_change_returns_the_new_sequence(self, hub):
        hub.start()
        result = []
        thread = threading.Thread(target=lambda: result.append(hub.wait_for_change(1, 3)))
        thread.start()
        time.sleep(0.05)
        hub.publish()
        thread.join(3)
        assert result == [2]

    def test_wait_for_change_returns_at_once_when_already_behind(self, hub):
        hub.publish()
        hub.start()
        assert wait_until(lambda: hub.seq() == 2)
        started = time.monotonic()
        assert hub.wait_for_change(1, 5) == 2
        assert time.monotonic() - started < 0.1

    def test_wait_for_change_times_out_with_none(self, hub):
        started = time.monotonic()
        assert hub.wait_for_change(1, 0.1) is None
        assert time.monotonic() - started >= 0.09

    def test_stop_releases_a_waiter(self, hub):
        hub.start()
        result = []
        thread = threading.Thread(target=lambda: result.append(hub.wait_for_change(1, 10)))
        thread.start()
        time.sleep(0.05)
        hub.stop()
        thread.join(2)
        assert not thread.is_alive()
        assert result == [None]

    def test_the_state_is_built_once_per_sequence(self, core):
        calls = []

        def build(seq):
            calls.append(seq)
            time.sleep(0.02)
            return b"x%d" % seq

        hub = ChangeHub(core, builder=build)
        results = []
        threads = [threading.Thread(target=lambda: results.append(hub.state())) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(3)
        assert calls == [1]
        assert results == [(1, b"x1")] * 8
        hub.publish()
        hub.start()
        assert wait_until(lambda: hub.seq() == 2)
        assert hub.state() == (2, b"x2")
        assert calls == [1, 2]
        hub.stop()

    def test_state_without_a_builder_is_an_error(self, core):
        with pytest.raises(RuntimeError):
            ChangeHub(core).state()


class TestWatchFollow:
    def watches(self, core):
        return [w for w in core.watches]

    def with_focus(self, core, manual=None, reporting=None):
        focus = dataclasses.replace(core.snapshot().focus, manual_id=manual, reporting_id=reporting)
        core.publish(focus=focus)

    def test_nothing_is_watched_with_no_client(self, hub, core):
        hub.start()
        core.publish(polling=False)
        time.sleep(0.1)
        assert core.watches == []

    def test_a_client_starts_the_follow_and_leaving_ends_it(self, hub, core):
        clients = [0]
        hub.set_client_counter(lambda: clients[0])
        hub.start()
        clients[0] = 1
        hub.poke()
        assert wait_until(lambda: len(core.watches) == 2)
        assert core.watches == [
            ("outputs", hs.LOUNGE, "hd", True), ("eq", hs.LOUNGE, "hd", True)]
        clients[0] = 0
        hub.poke()
        assert wait_until(lambda: len(core.watches) == 4)
        assert core.watches[2:] == [
            ("outputs", hs.LOUNGE, "hd", False), ("eq", hs.LOUNGE, "hd", False)]

    def test_the_follow_moves_with_focus(self, hub, core):
        hub.set_client_counter(lambda: 1)
        hub.start()
        hub.poke()
        assert wait_until(lambda: len(core.watches) == 2)
        self.with_focus(core, manual=hs.KITCHEN, reporting=hs.LOUNGE)
        assert wait_until(lambda: len(core.watches) == 4)
        assert core.watches[2:] == [
            ("outputs", hs.KITCHEN, "hd", True), ("eq", hs.KITCHEN, "hd", True)]

    def test_losing_focus_drops_the_watch(self, hub, core):
        hub.set_client_counter(lambda: 1)
        hub.start()
        hub.poke()
        assert wait_until(lambda: len(core.watches) == 2)
        self.with_focus(core, manual=None, reporting=None)
        assert wait_until(lambda: len(core.watches) == 4)
        assert core.watches[2:] == [
            ("outputs", hs.LOUNGE, "hd", False), ("eq", hs.LOUNGE, "hd", False)]

    def test_an_unchanged_focus_is_not_registered_again(self, hub, core):
        hub.set_client_counter(lambda: 1)
        hub.start()
        hub.poke()
        assert wait_until(lambda: len(core.watches) == 2)
        for _ in range(5):
            core.publish(polling=False)
            time.sleep(0.02)
        time.sleep(0.1)
        assert len(core.watches) == 2

    def test_stop_drops_the_watch(self, hub, core):
        hub.set_client_counter(lambda: 1)
        hub.start()
        hub.poke()
        assert wait_until(lambda: len(core.watches) == 2)
        hub.stop()
        assert core.watches[2:] == [
            ("outputs", hs.LOUNGE, "hd", False), ("eq", hs.LOUNGE, "hd", False)]

    def test_a_failing_core_call_does_not_stop_the_hub(self, hub, core):
        def boom(*args, **kwargs):
            raise RuntimeError("core went away")

        core.watch_outputs = boom
        hub.set_client_counter(lambda: 1)
        hub.start()
        hub.poke()
        time.sleep(0.1)
        core.publish(polling=False)
        assert wait_until(lambda: hub.seq() >= 2)
        hub.stop()


# ---- the stream over a real socket -----------------------------------------


class Sse:
    """A raw event-stream client."""

    def __init__(self, port, headers=None, rcvbuf=None, read_headers=True):
        self.sock = socket.socket()
        if rcvbuf:
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, rcvbuf)
        self.sock.settimeout(5)
        self.sock.connect(("127.0.0.1", port))
        lines = [f"GET /api/v1/events HTTP/1.1", f"Host: 127.0.0.1:{port}"]
        lines += [f"{k}: {v}" for k, v in (headers or {}).items()]
        self.sock.sendall(("\r\n".join(lines) + "\r\n\r\n").encode())
        self.buf = b""
        self.head = ""
        if read_headers:
            self.head = self._until(b"\r\n\r\n").decode()

    @property
    def status(self) -> int:
        return int(self.head.split(" ", 2)[1])

    def _until(self, marker: bytes, timeout=5.0) -> bytes:
        deadline = time.monotonic() + timeout
        while marker not in self.buf:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError(marker)
            self.sock.settimeout(remaining)
            try:
                chunk = self.sock.recv(65536)
            except socket.timeout:
                raise TimeoutError(marker)
            if not chunk:
                raise EOFError
            self.buf += chunk
        part, _, self.buf = self.buf.partition(marker)
        return part

    def block(self, timeout=5.0) -> str:
        """The next event or comment block."""
        return self._until(b"\n\n", timeout).decode()

    def event(self, timeout=5.0) -> dict:
        """The next state event, skipping comments."""
        while True:
            block = self.block(timeout)
            if block.startswith(":"):
                continue
            fields = dict(line.split(": ", 1) for line in block.split("\n"))
            fields["json"] = json.loads(fields["data"])
            return fields

    def silent_for(self, seconds: float) -> bool:
        try:
            self.block(seconds)
        except TimeoutError:
            return True
        return False

    def closed_by_server(self, timeout=3.0) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                self.sock.settimeout(0.2)
                if self.sock.recv(65536) == b"":
                    return True
            except socket.timeout:
                continue
            except OSError:
                return True
        return False

    def close(self):
        self.sock.close()


@pytest.fixture
def stack(monkeypatch, core):
    """A started hub and HdServer, with short heartbeat and write timeout."""
    monkeypatch.setattr(hde, "SSE_HEARTBEAT_S", 0.2)
    monkeypatch.setattr(hds, "CLIENT_WRITE_TIMEOUT_S", 0.3)
    hub = ChangeHub(core)
    server = hds.HdServer(
        SimpleNamespace(), core, hub=hub, port=0, muted_fn=lambda s: False,
        http_server=None,
    )
    hub.start()
    server.start()
    clients = []
    yield SimpleNamespace(hub=hub, server=server, core=core, clients=clients)
    for client in clients:
        client.close()
    server.stop()
    hub.stop()


def connect(stack, **kwargs) -> Sse:
    client = Sse(stack.server.port, **kwargs)
    stack.clients.append(client)
    return client


class TestEventStream:
    def test_the_stream_headers(self, stack):
        client = connect(stack)
        head = client.head.lower()
        assert client.status == 200
        assert "content-type: text/event-stream" in head
        assert "cache-control: no-store" in head
        assert "x-accel-buffering: no" in head
        assert "access-control" not in head

    def test_the_first_event_is_the_current_state(self, stack):
        client = connect(stack)
        event = client.event()
        assert event["event"] == "state"
        assert int(event["id"]) == stack.hub.seq()
        body = event["json"]
        assert body["seq"] == int(event["id"])
        assert body["core_seq"] == stack.core.snapshot().seq
        assert body["now_playing"]["title"] == "Tunnel of Love"

    def test_a_change_sends_the_full_state_under_a_new_id(self, stack):
        client = connect(stack)
        first = client.event()
        stack.core.publish(polling=False)
        second = client.event()
        assert int(second["id"]) > int(first["id"])
        assert second["json"]["polling"] is False
        assert second["json"]["core_seq"] == stack.core.snapshot().seq
        assert second["json"]["now_playing"]["title"] == "Tunnel of Love"   # full state, not a delta

    def test_the_state_route_and_the_stream_agree(self, stack):
        client = connect(stack)
        event = client.event()
        conn = http.client.HTTPConnection("127.0.0.1", stack.server.port, timeout=5)
        conn.request("GET", "/api/v1/state")
        body = json.loads(conn.getresponse().read())
        assert body == event["json"]

    def test_a_burst_of_changes_is_coalesced_and_ends_on_the_last(self, stack):
        client = connect(stack)
        client.event()
        for _ in range(30):
            stack.core.publish(polling=True)
        last_core_seq = stack.core.snapshot().seq
        events = []
        while True:
            events.append(client.event())
            if events[-1]["json"]["core_seq"] == last_core_seq:
                break
        assert len(events) < 30
        ids = [int(e["id"]) for e in events]
        assert ids == sorted(set(ids))

    def test_a_heartbeat_is_sent_when_nothing_changes(self, stack):
        client = connect(stack)
        client.event()
        started = time.monotonic()
        assert client.block(2) == ": ping"
        assert time.monotonic() - started < 1.0

    def test_last_event_id_behind_gets_the_state_at_once(self, stack):
        stack.core.publish(polling=False)
        assert wait_until(lambda: stack.hub.seq() == 2)
        client = connect(stack, headers={"Last-Event-ID": "1"})
        event = client.event(1)
        assert int(event["id"]) == 2

    def test_last_event_id_current_gets_only_pings(self, stack):
        stack.core.publish(polling=False)
        assert wait_until(lambda: stack.hub.seq() == 2)
        client = connect(stack, headers={"Last-Event-ID": "2"})
        assert client.block(2) == ": ping"
        stack.core.publish(polling=True)
        assert int(client.event()["id"]) == 3

    @pytest.mark.parametrize("value", ["abc", "", "99999", "-4"])
    def test_an_unusable_or_future_last_event_id_gets_the_state(self, stack, value):
        client = connect(stack, headers={"Last-Event-ID": value})
        assert int(client.event(2)["id"]) == stack.hub.seq()

    def test_the_cap_is_four_clients_and_the_next_is_refused(self, stack):
        assert SSE_MAX_CLIENTS == 4
        clients = [connect(stack) for _ in range(SSE_MAX_CLIENTS)]
        events = [c.event() for c in clients]
        assert len({e["id"] for e in events}) == 1
        assert stack.server.client_count() == 4
        refused = connect(stack)
        assert refused.status == 503
        assert b"too_many_clients" in (refused.buf or refused.sock.recv(4096))
        assert stack.server.client_count() == 4

    def test_a_slot_frees_when_a_client_leaves(self, stack):
        clients = [connect(stack) for _ in range(SSE_MAX_CLIENTS)]
        for c in clients:
            c.event()
        clients[0].close()
        assert wait_until(lambda: stack.server.client_count() == 3)
        fresh = connect(stack)
        assert fresh.status == 200
        fresh.event()

    def test_a_client_that_closes_is_noticed_without_any_write(self, stack, monkeypatch):
        # A reloaded page drops its stream silently; with the heartbeat far
        # away the server must still see the close and free the slot.
        monkeypatch.setattr(hde, "SSE_HEARTBEAT_S", 60.0)
        monkeypatch.setattr(hde, "SSE_LIVENESS_S", 0.1)
        clients = [connect(stack) for _ in range(SSE_MAX_CLIENTS)]
        for c in clients:
            c.event()
        assert stack.server.client_count() == SSE_MAX_CLIENTS
        for c in clients:
            c.close()
        assert wait_until(lambda: stack.server.client_count() == 0, timeout=2.0)
        fresh = connect(stack)
        assert fresh.status == 200

    def test_a_quiet_client_is_not_mistaken_for_a_closed_one(self, stack, monkeypatch):
        monkeypatch.setattr(hde, "SSE_HEARTBEAT_S", 60.0)
        monkeypatch.setattr(hde, "SSE_LIVENESS_S", 0.05)
        client = connect(stack)
        client.event()
        time.sleep(0.4)
        assert stack.server.client_count() == 1
        stack.core.publish()
        assert client.event()["json"]["seq"]

    def test_the_client_count_follows_connections(self, stack):
        assert stack.server.client_count() == 0
        a = connect(stack)
        a.event()
        assert stack.server.client_count() == 1
        a.close()
        assert wait_until(lambda: stack.server.client_count() == 0)

    def test_a_bad_host_is_refused_before_the_stream_starts(self, stack):
        conn = http.client.HTTPConnection("127.0.0.1", stack.server.port, timeout=5)
        conn.putrequest("GET", "/api/v1/events", skip_host=True)
        conn.putheader("Host", "evil.example")
        conn.endheaders()
        assert conn.getresponse().status == 403
        assert stack.server.client_count() == 0

    def test_without_a_hub_the_route_is_not_found(self, core):
        server = hds.HdServer(SimpleNamespace(), core, port=0, muted_fn=lambda s: False)
        server.start()
        try:
            conn = http.client.HTTPConnection("127.0.0.1", server.port, timeout=5)
            conn.request("GET", "/api/v1/events")
            assert conn.getresponse().status == 404
        finally:
            server.stop()


class TestSlowClients:
    def test_a_client_that_never_reads_is_dropped_and_nothing_else_is_held_up(self, stack):
        core = stack.core
        healthy = connect(stack)
        healthy.event()
        stalled = connect(stack, rcvbuf=2048)       # reads its headers, then never reads again
        assert stack.server.client_count() == 2

        received = []
        reader_done = threading.Event()

        def drain():
            try:
                while True:
                    received.append(healthy.event(5))
            except (TimeoutError, EOFError, OSError):
                pass
            reader_done.set()

        threading.Thread(target=drain, daemon=True).start()

        latencies = []
        waiter_results = []

        def waiter():
            seen = core.snapshot().seq
            waiter_results.append(core.wait_for_change(seen, 5))

        waiter_thread = threading.Thread(target=waiter, daemon=True)
        waiter_thread.start()

        deadline = time.monotonic() + 8
        while time.monotonic() < deadline and stack.server.client_count() != 1:
            started = time.monotonic()
            core.publish(polling=True)
            latencies.append(time.monotonic() - started)
            time.sleep(0.003)

        assert stack.server.client_count() == 1, "the stalled client was not dropped"
        assert max(latencies) < 0.05                 # publishing never waited on the stalled socket
        waiter_thread.join(2)
        assert waiter_results and waiter_results[0] is not None

        # The healthy client kept up and is still being served.
        last = core.snapshot().seq
        core.publish(polling=False)
        final = core.snapshot().seq
        assert wait_until(lambda: received and received[-1]["json"]["core_seq"] == final, 3)
        assert last < final
        conn = http.client.HTTPConnection("127.0.0.1", stack.server.port, timeout=5)
        conn.request("GET", "/api/v1/state")
        assert conn.getresponse().status == 200

    def test_a_stalled_client_does_not_delay_the_hub_sequence(self, stack):
        stalled = connect(stack, rcvbuf=2048)
        for _ in range(50):
            stack.core.publish(polling=True)
            time.sleep(0.002)
        before = stack.hub.seq()
        stack.core.publish(polling=False)
        assert wait_until(lambda: stack.hub.seq() > before, 1.0)

    def test_stopping_the_server_ends_every_client_within_a_heartbeat(self, stack):
        clients = [connect(stack) for _ in range(3)]
        for c in clients:
            c.event()
        stack.server.stop()
        for c in clients:
            assert c.closed_by_server(2.0)
        assert wait_until(lambda: stack.server.client_count() == 0, 2.0)


class TestWatchFollowWithClients:
    def test_the_follow_runs_only_while_a_client_is_connected(self, stack):
        core = stack.core
        core.publish(polling=False)
        time.sleep(0.1)
        assert core.watches == []
        client = connect(stack)
        client.event()
        assert wait_until(lambda: len(core.watches) == 2)
        assert ("outputs", hs.LOUNGE, "hd", True) in core.watches
        assert ("eq", hs.LOUNGE, "hd", True) in core.watches
        client.close()
        assert wait_until(lambda: len(core.watches) == 4)
        assert ("outputs", hs.LOUNGE, "hd", False) in core.watches
        assert ("eq", hs.LOUNGE, "hd", False) in core.watches

    def test_a_second_client_does_not_register_again(self, stack):
        a = connect(stack)
        a.event()
        assert wait_until(lambda: len(stack.core.watches) == 2)
        b = connect(stack)
        b.event()
        time.sleep(0.15)
        assert len(stack.core.watches) == 2
        a.close()
        time.sleep(0.5)
        assert len(stack.core.watches) == 2        # b is still connected
