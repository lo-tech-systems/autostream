"""Event sources: the owntone-mini socket, the upstream websocket and polling.

Streams are recorded protocol lines (tests/fixtures/events). Sockets, clocks
and the websocket module are fakes; no test connects to a player.
"""
from __future__ import annotations

import errno
import json
import socket
import sys
import threading
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
_core = str(REPO_ROOT / "core")
if _core not in sys.path:
    sys.path.insert(0, _core)

import autostream_backend_events as be
from autostream_players import EventChannelInfo

FIXTURES = Path(__file__).parent / "fixtures" / "events"


def fixture_bytes(*names: str) -> bytes:
    return b"".join((FIXTURES / name).read_bytes() for name in names)


class FakeClock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


class ScriptedSocket:
    """A socket that plays a script: bytes are received, ("idle", seconds)
    advances the clock and times out, anything exhausted reads as EOF."""

    def __init__(self, clock: FakeClock, *script) -> None:
        self.clock = clock
        self.script = list(script)
        self.sent: list[dict] = []
        self.timeouts: list[float] = []
        self.closed = False

    def settimeout(self, value) -> None:
        self.timeouts.append(value)

    def recv(self, _n: int) -> bytes:
        if not self.script:
            return b""
        item = self.script.pop(0)
        if isinstance(item, tuple) and item[0] == "idle":
            self.clock.now += item[1]
            raise socket.timeout()
        if isinstance(item, BaseException):
            raise item
        return item

    def sendall(self, data: bytes) -> None:
        for line in data.splitlines():
            self.sent.append(json.loads(line))

    def shutdown(self, _how) -> None:
        pass

    def close(self) -> None:
        self.closed = True


class RecordingSink:
    def __init__(self) -> None:
        self.calls: list[tuple] = []
        self.connected_event = threading.Event()

    def on_connected(self, info) -> None:
        self.calls.append(("connected", info))
        self.connected_event.set()

    def on_disconnected(self, reason) -> None:
        self.calls.append(("disconnected", reason))

    def on_outputs_changed(self) -> None:
        self.calls.append(("changed",))

    def on_device_event(self, ev) -> None:
        self.calls.append(("event", ev))

    def names(self) -> list[str]:
        return [c[0] for c in self.calls]


class FakeStop:
    """Stands in for the source's stop Event so a loop runs on the test's
    thread: wait() records the delay and the flag is set after *rounds*."""

    def __init__(self, rounds: int) -> None:
        self.rounds = rounds
        self.waits: list[float] = []
        self.flag = False

    def is_set(self) -> bool:
        return self.flag

    def set(self) -> None:
        self.flag = True

    def clear(self) -> None:
        self.flag = False

    def wait(self, timeout=None) -> bool:
        self.waits.append(timeout)
        if len(self.waits) >= self.rounds:
            self.flag = True
        return self.flag


def make_source(clock=None, **kw) -> be.UnixSocketEventSource:
    return be.UnixSocketEventSource("/run/test/events.sock", client_name="autostream",
                                    clock=clock or FakeClock(), **kw)


def serve(script, *, clock=None, source=None):
    clock = clock or FakeClock()
    source = source or make_source(clock)
    sink = RecordingSink()
    sock = ScriptedSocket(clock, *script)
    result = source.serve(sock, sink)
    return source, sink, sock, result


# ---------------------------------------------------------------------------
# Unix socket: one connection
# ---------------------------------------------------------------------------

class TestUnixConnection:
    def test_it_sends_the_hello_first(self):
        _source, _sink, sock, _result = serve([fixture_bytes("hello.jsonl")])
        assert sock.sent[0] == {"type": "hello", "protocol": 1, "client": "autostream"}

    def test_the_hello_gives_the_connect_info(self):
        _source, sink, _sock, _result = serve([fixture_bytes("hello.jsonl")])
        info = sink.calls[0][1]
        assert sink.names()[0] == "connected"
        assert info.boot == "3f9a1c2e77b04d15"
        assert info.uptime_ms == 1843
        assert info.capabilities == frozenset({"changed", "receiver_command", "device_volume", "include_tv"})
        assert info.kind == "unix_socket"

    def test_changed_and_both_event_kinds_reach_the_sink(self):
        clock = FakeClock()
        _source, sink, _sock, _result = serve(
            [fixture_bytes("hello.jsonl", "stream.jsonl")], clock=clock)
        assert sink.names() == ["connected", "changed", "event", "event", "disconnected"]
        command, volume = sink.calls[2][1], sink.calls[3][1]
        assert (command.kind, command.speaker_id, command.speaker_name, command.verb, command.value, command.at_ms) == (
            "receiver_command", "9988776655443322", "TV A", "paus", None, 190511)
        assert (volume.kind, volume.speaker_id, volume.verb, volume.value) == (
            "device_volume", "8734567012345678", "volumeup", "45")
        assert command.received == clock.now
        assert (command.member_id, volume.member_id) == ("9988776655443399", "8734567012345678")

    def test_member_id_is_none_when_absent_or_not_a_string(self):
        def source_for(speaker):
            line = json.dumps({"type": "event", "seq": 3, "kind": "receiver_command", "verb": "paus",
                               "speaker": speaker, "at_ms": 1}).encode() + b"\n"
            _source, sink, _sock, _result = serve([fixture_bytes("hello.jsonl") + line])
            return sink.calls[1][1]
        assert source_for({"id": "1", "name": "A"}).member_id is None
        assert source_for({"id": "1", "member_id": 7, "name": "A"}).member_id is None
        assert source_for({"id": "1", "member_id": "2", "name": "A"}).member_id == "2"

    def test_the_all_speakers_volume_keeps_id_zero_and_a_null_name(self):
        _source, sink, _sock, _result = serve([fixture_bytes("hello.jsonl", "all_speakers_volume.jsonl")])
        event = sink.calls[1][1]
        assert (event.speaker_id, event.speaker_name, event.value) == ("0", None, "30")

    def test_unknown_types_fields_and_event_kinds_are_ignored(self):
        _source, sink, _sock, _result = serve([fixture_bytes("hello.jsonl", "unknown.jsonl")])
        assert sink.names() == ["connected", "changed", "disconnected"]

    def test_a_line_that_is_not_json_is_skipped(self):
        _source, sink, _sock, _result = serve(
            [fixture_bytes("hello.jsonl") + b"not json\n[1,2]\n" + fixture_bytes("pong.jsonl")])
        assert sink.names() == ["connected", "disconnected"]

    def test_lines_split_across_reads_are_joined(self):
        data = fixture_bytes("hello.jsonl", "stream.jsonl")
        chunks = [data[i:i + 7] for i in range(0, len(data), 7)]
        _source, sink, _sock, _result = serve(chunks)
        assert sink.names() == ["connected", "changed", "event", "event", "disconnected"]

    def test_pongs_are_counted(self):
        source, _sink, _sock, _result = serve([fixture_bytes("hello.jsonl", "pong.jsonl")])
        assert source.pongs == 1

    def test_an_error_message_closes_the_connection(self):
        _source, sink, _sock, (reason, good) = serve(
            [fixture_bytes("hello.jsonl", "error.jsonl", "stream.jsonl")])
        assert reason == "error:shutting_down"
        assert good is True
        assert sink.names() == ["connected", "disconnected"]
        assert sink.calls[-1] == ("disconnected", "error:shutting_down")

    def test_an_error_instead_of_a_hello_is_a_failed_attempt(self, caplog):
        _source, sink, _sock, (reason, good) = serve([fixture_bytes("not_allowed.jsonl")])
        assert reason == "error:not_allowed"
        assert good is False
        assert sink.calls == []

    def test_a_hello_of_another_protocol_is_refused(self):
        _source, sink, _sock, (reason, good) = serve([fixture_bytes("hello_protocol2.jsonl", "stream.jsonl")])
        assert reason == "protocol:2"
        assert good is False
        assert sink.calls == []

    def test_no_hello_within_the_timeout_is_a_failed_attempt(self):
        clock = FakeClock()
        _source, sink, sock, (reason, good) = serve([("idle", 15)], clock=clock)
        assert (reason, good) == ("hello timeout", False)
        assert sock.timeouts[0] == 15.0
        assert sink.calls == []

    def test_a_line_over_the_server_limit_closes_the_connection(self):
        too_long = b"x" * (be.MAX_SERVER_LINE + 10)
        _source, sink, _sock, (reason, _good) = serve([fixture_bytes("hello.jsonl"), too_long])
        assert reason == "line too long"
        assert sink.names() == ["connected", "disconnected"]

    def test_a_long_line_under_the_limit_is_read(self):
        padded = json.dumps({"type": "changed", "what": "outputs", "pad": "y" * 50000}).encode() + b"\n"
        _source, sink, _sock, _result = serve([fixture_bytes("hello.jsonl"), padded])
        assert sink.names() == ["connected", "changed", "disconnected"]

    def test_eof_ends_the_connection(self):
        _source, sink, _sock, (reason, good) = serve([fixture_bytes("hello.jsonl")])
        assert (reason, good) == ("closed by the server", True)
        assert sink.calls[-1] == ("disconnected", "closed by the server")


class TestUnixKeepAlive:
    def test_a_ping_with_a_counter_goes_out_every_ten_seconds(self):
        hello = fixture_bytes("hello.jsonl")
        pong = fixture_bytes("pong.jsonl")
        _source, _sink, sock, _result = serve([hello, ("idle", 10), pong, ("idle", 10), pong, ("idle", 4)])
        pings = [m for m in sock.sent if m["type"] == "ping"]
        assert [p["t"] for p in pings] == [1, 2]

    def test_no_ping_before_the_interval(self):
        _source, _sink, sock, _result = serve([fixture_bytes("hello.jsonl"), ("idle", 9)])
        assert [m for m in sock.sent if m["type"] == "ping"] == []

    def test_no_pong_for_thirty_seconds_closes_for_a_reconnect(self):
        hello = fixture_bytes("hello.jsonl")
        _source, sink, sock, (reason, good) = serve([hello, ("idle", 10), ("idle", 10), ("idle", 10), hello])
        assert (reason, good) == ("no pong", True)
        assert sink.calls[-1] == ("disconnected", "no pong")

    def test_a_pong_keeps_the_connection_open(self):
        hello = fixture_bytes("hello.jsonl")
        pong = fixture_bytes("pong.jsonl")
        script = [hello]
        for _ in range(5):
            script += [("idle", 10), pong]
        _source, _sink, _sock, (reason, _good) = serve(script)
        assert reason == "closed by the server"


# ---------------------------------------------------------------------------
# Unix socket: the connection loop
# ---------------------------------------------------------------------------

class TestUnixReconnect:
    def test_the_back_off_steps_up_and_stays_at_five_seconds(self):
        source = make_source()
        assert [source._delay(n) for n in range(7)] == [0.5, 1.0, 2.0, 5.0, 5.0, 5.0, 5.0]

    def _run(self, connects, rounds, clock=None):
        clock = clock or FakeClock()
        source = make_source(clock, connect=connects)
        source._sink = RecordingSink()
        source._stop = FakeStop(rounds)
        source._run()
        return source

    def test_a_missing_socket_is_quiet_and_retried_with_back_off(self, caplog):
        def connect(path):
            raise FileNotFoundError(errno.ENOENT, "no such file", path)

        with caplog.at_level("DEBUG"):
            source = self._run(connect, 6)
        assert source._stop.waits == [0.5, 1.0, 2.0, 5.0, 5.0, 5.0]
        assert not [r for r in caplog.records if r.levelname in ("WARNING", "ERROR")]

    def test_a_refused_connection_is_quiet(self, caplog):
        def connect(path):
            raise ConnectionRefusedError(errno.ECONNREFUSED, "refused")

        with caplog.at_level("DEBUG"):
            self._run(connect, 3)
        assert not [r for r in caplog.records if r.levelname in ("WARNING", "ERROR")]

    def test_the_back_off_restarts_after_a_good_hello(self):
        clock = FakeClock()
        attempts = []

        def connect(path):
            attempts.append(path)
            if len(attempts) == 3:
                return ScriptedSocket(clock, fixture_bytes("hello.jsonl"))
            raise FileNotFoundError(errno.ENOENT, "no such file")

        source = self._run(connect, 4, clock)
        assert source._stop.waits == [0.5, 1.0, 0.5, 1.0]

    def test_the_boot_id_is_passed_on_each_reconnect(self):
        clock = FakeClock()
        boots = ["aaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbb"]

        def hello(boot):
            return json.dumps({"type": "hello", "protocol": 1, "boot": boot, "uptime_ms": 5,
                               "capabilities": ["changed"]}).encode() + b"\n"

        def connect(path):
            return ScriptedSocket(clock, hello(boots.pop(0)))

        source = self._run(connect, 2, clock)
        seen = [c[1].boot for c in source._sink.calls if c[0] == "connected"]
        assert seen == ["aaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbb"]

    def test_another_failure_is_logged_once_and_the_recovery_is_logged(self, caplog):
        clock = FakeClock()
        attempts = []

        def connect(path):
            attempts.append(path)
            if len(attempts) <= 2:
                raise PermissionError(errno.EACCES, "denied")
            return ScriptedSocket(clock, fixture_bytes("hello.jsonl"))

        with caplog.at_level("DEBUG"):
            self._run(connect, 3, clock)
        warnings = [r.getMessage() for r in caplog.records if r.levelname == "WARNING"]
        assert len([w for w in warnings if "could not connect" in w]) == 1
        assert len([w for w in warnings if "recovered after 2 failure(s)" in w]) == 1

    def test_the_socket_is_closed_when_the_connection_ends(self):
        clock = FakeClock()
        made = []

        def connect(path):
            made.append(ScriptedSocket(clock, fixture_bytes("hello.jsonl")))
            return made[-1]

        self._run(connect, 1, clock)
        assert made[0].closed is True


class TestUnixThread:
    def test_stop_says_goodbye_closes_and_joins(self):
        clock = FakeClock()

        class BlockingSocket(ScriptedSocket):
            def __init__(self):
                super().__init__(clock)
                self.first = True
                self.release = threading.Event()

            def recv(self, n):
                if self.first:
                    self.first = False
                    return fixture_bytes("hello.jsonl")
                self.release.wait(5)
                raise socket.timeout()

            def close(self):
                super().close()
                self.release.set()

            shutdown = None

        sock = BlockingSocket()
        source = be.UnixSocketEventSource("/run/test/events.sock", client_name="autostream",
                                          connect=lambda path: sock)
        sink = RecordingSink()
        source.start(sink)
        assert sink.connected_event.wait(5)
        assert source.connected is True
        source.stop(timeout=5)
        assert sock.sent[-1] == {"type": "goodbye"}
        assert sock.closed is True
        assert source.connected is False
        assert source._thread is None


# ---------------------------------------------------------------------------
# Polling
# ---------------------------------------------------------------------------

class TestPollSource:
    def test_it_reports_outputs_changed_on_the_callable_cadence(self):
        intervals = iter([2.0, 5.0, 2.0])
        source = be.PollEventSource(lambda: next(intervals))
        source._sink = RecordingSink()
        source._stop = FakeStop(3)
        source._run()
        assert source._stop.waits == [2.0, 5.0, 2.0]
        assert source._sink.names() == ["changed", "changed"]

    def test_a_failing_interval_callable_falls_back_to_five_seconds(self):
        def broken():
            raise RuntimeError("no interval")

        source = be.PollEventSource(broken)
        source._sink = RecordingSink()
        source._stop = FakeStop(1)
        source._run()
        assert source._stop.waits == [5.0]

    def test_start_reports_one_connect_without_a_boot_and_stop_joins(self):
        source = be.PollEventSource(lambda: 3600.0)
        sink = RecordingSink()
        source.start(sink)
        try:
            assert source.connected is True
            info = sink.calls[0][1]
            assert (sink.calls[0][0], info.boot, info.capabilities, info.kind) == (
                "connected", None, frozenset(), "poll")
        finally:
            source.stop(timeout=5)
        assert source.connected is False


# ---------------------------------------------------------------------------
# Websocket
# ---------------------------------------------------------------------------

class FakeWebSocketApp:
    messages: list = []
    opens = True
    instances: list = []

    def __init__(self, url, **kw):
        self.url = url
        self.kw = kw
        self.sent: list = []
        self.closed = False
        FakeWebSocketApp.instances.append(self)

    def send(self, text):
        self.sent.append(text)

    def close(self):
        self.closed = True

    def run_forever(self, **kw):
        if FakeWebSocketApp.opens:
            self.kw["on_open"](self)
            for message in FakeWebSocketApp.messages:
                self.kw["on_message"](self, message)
        else:
            self.kw["on_error"](self, OSError("connection refused"))


class FakeWebSocketModule:
    WebSocketApp = FakeWebSocketApp


@pytest.fixture
def fake_ws():
    FakeWebSocketApp.messages = ['{"notify":["outputs"]}', '{"notify":["volume"]}']
    FakeWebSocketApp.opens = True
    FakeWebSocketApp.instances = []
    return FakeWebSocketModule


class TestWebSocketSource:
    def test_a_connection_subscribes_and_each_message_is_a_change(self, fake_ws):
        source = be.WebSocketEventSource("ws://host:3688", subprotocol="notify")
        source._sink = RecordingSink()
        opened = source.run_connection(fake_ws)
        app = FakeWebSocketApp.instances[0]
        assert opened is True
        assert app.url == "ws://host:3688"
        assert app.kw["subprotocols"] == ["notify"]
        assert json.loads(app.sent[0]) == {"notify": ["outputs", "volume"]}
        assert source._sink.names() == ["connected", "changed", "changed", "disconnected"]
        info = source._sink.calls[0][1]
        assert (info.boot, info.kind) == (None, "websocket")
        assert source._sink.calls[-1] == ("disconnected", "closed")

    def test_no_subprotocol_when_none_is_given(self, fake_ws):
        source = be.WebSocketEventSource("ws://host:3689/ws", subprotocol=None)
        source._sink = RecordingSink()
        source.run_connection(fake_ws)
        assert FakeWebSocketApp.instances[0].kw["subprotocols"] is None

    def test_a_missing_module_is_reported_once_and_degrades(self, caplog, monkeypatch):
        monkeypatch.setattr(be, "_websocket_import_logged", False)

        def missing(name):
            raise ImportError(name)

        with caplog.at_level("INFO"):
            for _ in range(2):
                source = be.WebSocketEventSource("ws://h:1", subprotocol=None, import_module=missing)
                sink = RecordingSink()
                source.start(sink)
                assert source.degraded is True
                assert sink.calls == [("disconnected", "degraded")]
        notes = [r.getMessage() for r in caplog.records if "python3-websocket not installed" in r.getMessage()]
        assert notes == ["python3-websocket not installed; polling the player instead"]

    def test_three_failed_connects_report_degraded(self, fake_ws):
        FakeWebSocketApp.opens = False
        source = be.WebSocketEventSource("ws://h:1", subprotocol="notify")
        source._sink = RecordingSink()
        source._stop = FakeStop(10)
        source._run(fake_ws)
        assert len(FakeWebSocketApp.instances) == 3
        assert source.degraded is True
        assert source._sink.calls == [("disconnected", "degraded")]
        assert source._stop.waits == [0.5, 1.0]

    def test_a_connection_that_opened_resets_the_failure_count(self, fake_ws):
        source = be.WebSocketEventSource("ws://h:1", subprotocol="notify")
        source._sink = RecordingSink()
        source._stop = FakeStop(5)
        outcomes = iter([False, False, True, False, False])
        source.run_connection = lambda module: next(outcomes)
        source._run(fake_ws)
        assert source.degraded is False
        assert source._stop.waits == [0.5, 1.0, 0.5, 0.5, 1.0]

    def test_start_imports_the_module_inside_start(self, fake_ws):
        imported = []

        def importer(name):
            imported.append(name)
            return fake_ws

        FakeWebSocketApp.messages = []
        source = be.WebSocketEventSource("ws://h:1", subprotocol=None, import_module=importer)
        assert imported == []
        sink = RecordingSink()
        source.start(sink)
        try:
            assert imported == ["websocket"]
            assert sink.connected_event.wait(5)
        finally:
            source.stop(timeout=5)


# ---------------------------------------------------------------------------
# Selection
# ---------------------------------------------------------------------------

class TestCreateEventSource:
    def _make(self, info, base_url="http://localhost:3689"):
        return be.create_event_source(info, base_url, poll_interval=lambda: 2.0)

    def test_a_unix_socket_with_a_path(self):
        source = self._make(EventChannelInfo(kind="unix_socket", protocol=1,
                                             socket_path="/run/owntone-mini/events.sock", reachable=True))
        assert isinstance(source, be.UnixSocketEventSource)
        assert source._path == "/run/owntone-mini/events.sock"
        assert source._client == "autostream"

    def test_a_unix_socket_without_a_path_polls(self):
        source = self._make(EventChannelInfo(kind="unix_socket", protocol=1, socket_path=None, reachable=True))
        assert isinstance(source, be.PollEventSource)

    def test_an_unreachable_probe_polls(self):
        for kind in ("unix_socket", "websocket", "poll"):
            source = self._make(EventChannelInfo(kind=kind, socket_path="/x", reachable=False))
            assert isinstance(source, be.PollEventSource), kind

    def test_a_websocket_port_uses_the_notify_subprotocol(self):
        source = self._make(EventChannelInfo(kind="websocket", websocket_port=3688, reachable=True),
                            "http://player.local:3689")
        assert isinstance(source, be.WebSocketEventSource)
        assert source._url == "ws://player.local:3688"
        assert source._subprotocol == "notify"

    def test_a_websocket_without_a_port_uses_the_http_port_and_path(self):
        source = self._make(EventChannelInfo(kind="websocket", websocket_port=0, reachable=True),
                            "http://player.local:3689")
        assert source._url == "ws://player.local:3689/ws"
        assert source._subprotocol is None

    def test_a_poll_description_polls(self):
        source = self._make(EventChannelInfo(kind="poll", reachable=True))
        assert isinstance(source, be.PollEventSource)

    def test_the_poll_source_uses_the_callable_it_is_given(self):
        source = self._make(EventChannelInfo(kind="poll", reachable=True))
        assert source._interval() == 2.0


# ---------------------------------------------------------------------------
# Installer
# ---------------------------------------------------------------------------

def test_the_installer_installs_the_websocket_package_softly_after_requests():
    text = (REPO_ROOT / "autostream_install.sh").read_text(encoding="utf-8")
    requests_at = text.index("apt_install --soft python3-requests")
    websocket_at = text.index("apt_install --soft python3-websocket")
    assert websocket_at > requests_at


class TestParseEvent:
    @staticmethod
    def msg(**over):
        base = {"type": "event", "seq": 3, "kind": "receiver_command", "verb": "paus",
                "speaker": {"id": "1001", "member_id": "1002", "name": "Speaker A"}, "at_ms": 190511}
        base.update(over)
        return base

    def test_a_receiver_command(self):
        ev = be.parse_event(self.msg(), 12.5)
        assert ev == be.DeviceEvent("receiver_command", "1001", "Speaker A", "paus", None, 190511, 12.5, "1002")

    def test_a_device_volume_carries_its_value(self):
        ev = be.parse_event(self.msg(kind="device_volume", verb="volumeup", value=45), 1.0)
        assert (ev.kind, ev.verb, ev.value) == ("device_volume", "volumeup", "45")

    def test_the_all_speakers_id_is_kept(self):
        ev = be.parse_event(self.msg(kind="device_volume", verb="dmcp.volume", value="60",
                                     speaker={"id": 0, "name": None}), 1.0)
        assert ev.speaker_id == "0" and ev.speaker_name is None and ev.member_id is None

    def test_the_member_id_must_be_a_string(self):
        ev = be.parse_event(self.msg(speaker={"id": "1", "member_id": 7}), 1.0)
        assert ev.member_id is None

    @pytest.mark.parametrize("msg", [
        {"kind": "receiver_command", "verb": "paus"},
        {"kind": "receiver_command", "verb": "paus", "speaker": {"name": "x"}},
        {"kind": "receiver_command", "speaker": {"id": "1"}},
        {"kind": "something_new", "verb": "paus", "speaker": {"id": "1"}},
        {"verb": "paus", "speaker": {"id": "1"}},
    ])
    def test_a_message_without_a_kind_speaker_or_verb_gives_none(self, msg):
        assert be.parse_event(msg, 1.0) is None
