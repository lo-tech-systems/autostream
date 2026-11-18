#!/usr/bin/env python3
"""autostream_backend_events.py

Event sources: how output changes and device events reach autostream from the
player. owntone-mini pushes them over a Unix socket, upstream OwnTone over a
websocket, and any other player is polled. Every source reports to a sink
whose methods only enqueue, so a source thread never waits on autostream.
"""

from __future__ import annotations

import errno
import importlib
import json
import logging
import socket
import threading
import time
from dataclasses import dataclass
from typing import Callable, Mapping, Optional, Protocol, Sequence
from urllib.parse import urlparse

import autostream_runtime as runtime
from autostream_players import EventChannelInfo


LOG = logging.getLogger(__name__)

PROTOCOL = 1
CLIENT_NAME = "autostream"

HELLO_TIMEOUT_S = 15.0
PING_INTERVAL_S = 10.0
PONG_DEADLINE_S = 30.0
# The server's own send cap; a longer line closes the connection.
MAX_SERVER_LINE = 256 * 1024
# Longest wait inside one read, so a stop request is seen promptly.
_READ_SLICE_S = 1.0
_BACKOFF_S = (0.5, 1.0, 2.0, 5.0, 5.0)
_QUIET_ERRNOS = (errno.ENOENT, errno.ECONNREFUSED)

WEBSOCKET_FAILURES_BEFORE_DEGRADED = 3
_WEBSOCKET_NOTIFY = ["outputs", "volume"]

DEGRADED = "degraded"


@dataclass(frozen=True)
class ConnectInfo:
    boot: Optional[str]  # hello.boot (16 hex); None for websocket and poll
    uptime_ms: Optional[int]
    capabilities: frozenset  # hello.capabilities; empty for websocket and poll
    kind: str


@dataclass(frozen=True)
class DeviceEvent:
    kind: str  # "receiver_command" | "device_volume"
    speaker_id: str  # the id as a string, "0" for an all-speakers volume
    speaker_name: Optional[str]
    verb: str
    value: Optional[str]  # device_volume only
    at_ms: int  # the player's monotonic clock, same origin as uptime_ms
    received: float  # time.monotonic() at the sink
    member_id: Optional[str] = None  # the device the event came from; for logs
    protocol: Optional[str] = None  # receiver commands: where it came from; for logs


class EventSink(Protocol):
    """Implemented by the consumer; every method only enqueues."""

    def on_connected(self, info: ConnectInfo) -> None: ...

    def on_disconnected(self, reason: str) -> None: ...

    def on_outputs_changed(self) -> None: ...

    def on_device_event(self, ev: DeviceEvent) -> None: ...


class EventSource:
    """Base of the three sources."""

    kind = "poll"

    def start(self, sink: EventSink) -> None:
        raise NotImplementedError

    def stop(self, timeout: float = 2.0) -> None:
        raise NotImplementedError

    @property
    def connected(self) -> bool:
        return False


def _call_sink(method: Callable, *args) -> None:
    """A sink only enqueues; a failure in one must not end a source thread."""
    try:
        method(*args)
    except Exception:
        LOG.exception("Event sink call failed")


def parse_event(msg: Mapping, received: float) -> Optional[DeviceEvent]:
    """One server "event" message as a DeviceEvent (member_id included), or
    None for an unknown kind or a message without a speaker or verb (a DEBUG
    line)."""
    kind = msg.get("kind")
    if kind not in ("receiver_command", "device_volume"):
        return None
    speaker = msg.get("speaker")
    verb = msg.get("verb")
    if not isinstance(speaker, dict) or not isinstance(verb, str) or speaker.get("id") is None:
        LOG.debug("owntone-mini events: %s event without a speaker or verb ignored", kind)
        return None
    name = speaker.get("name")
    member_id = speaker.get("member_id")
    value = msg.get("value")
    at_ms = msg.get("at_ms")
    protocol = msg.get("protocol")
    return DeviceEvent(
        kind=kind,
        speaker_id=str(speaker.get("id")),
        speaker_name=name if isinstance(name, str) else None,
        verb=verb,
        value=None if value is None or kind != "device_volume" else str(value),
        at_ms=at_ms if isinstance(at_ms, int) and not isinstance(at_ms, bool) else 0,
        received=received,
        member_id=member_id if isinstance(member_id, str) else None,
        protocol=protocol if kind == "receiver_command" and isinstance(protocol, str) else None,
    )


class _Closed(Exception):
    """The connection ended; the text says why."""


class UnixSocketEventSource(EventSource):
    """owntone-mini's notifier socket (one JSON object per line)."""

    kind = "unix_socket"

    def __init__(
        self,
        socket_path: str,
        *,
        client_name: str = CLIENT_NAME,
        connect: Optional[Callable[[str], "socket.socket"]] = None,
        clock: Callable[[], float] = time.monotonic,
        backoff: Sequence[float] = _BACKOFF_S,
    ) -> None:
        self._path = socket_path
        self._client = client_name
        self._connect = connect or _connect_unix
        self._clock = clock
        self._backoff = tuple(backoff) or _BACKOFF_S
        self._sink: Optional[EventSink] = None
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self._sock_lock = threading.Lock()  # leaf: guards _sock and _connected
        self._sock: Optional["socket.socket"] = None
        self._connected = False
        self._buf = bytearray()
        self._recovery = runtime.RecoveryLog("owntone-mini events")
        self._failure_logged = False
        self.pongs = 0

    # ------------------------------------------------------------------ API

    @property
    def connected(self) -> bool:
        with self._sock_lock:
            return self._connected

    def start(self, sink: EventSink) -> None:
        if self._thread is not None:
            return
        self._sink = sink
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="outputs-events", daemon=True)
        self._thread.start()

    def stop(self, timeout: float = 2.0) -> None:
        self._stop.set()
        with self._sock_lock:
            sock = self._sock
            was_connected = self._connected
        if sock is not None:
            if was_connected:
                self._send(sock, {"type": "goodbye"})
            _close_socket(sock)
        thread = self._thread
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout)
        self._thread = None

    # ----------------------------------------------------------- the thread

    def _run(self) -> None:
        failures = 0
        while not self._stop.is_set():
            sock = None
            try:
                sock = self._connect(self._path)
            except OSError as exc:
                self._note_connect_failure(exc)
                self._stop.wait(self._delay(failures))
                failures += 1
                continue
            with self._sock_lock:
                self._sock = sock
            if self._stop.is_set():
                _close_socket(sock)
                break
            reason, good = self.serve(sock, self._sink)
            with self._sock_lock:
                self._sock = None
            _close_socket(sock)
            if good:
                failures = 0
            if self._stop.is_set():
                break
            self._stop.wait(self._delay(failures))
            failures += 1

    def _delay(self, failures: int) -> float:
        return self._backoff[min(failures, len(self._backoff) - 1)]

    def _note_connect_failure(self, exc: OSError) -> None:
        if getattr(exc, "errno", None) in _QUIET_ERRNOS or isinstance(
            exc, (FileNotFoundError, ConnectionRefusedError)
        ):
            LOG.debug("owntone-mini events: %s not available (%s)", self._path, exc)
            return
        self._fail(f"could not connect to {self._path}: {exc}")

    def _fail(self, text: str) -> None:
        now = self._clock()
        if not self._failure_logged:
            self._failure_logged = True
            LOG.warning("owntone-mini events: %s", text)
        else:
            LOG.debug("owntone-mini events: %s", text)
        self._recovery.fail(now)

    # ----------------------------------------------------- one connection

    def serve(self, sock: "socket.socket", sink: EventSink) -> tuple[str, bool]:
        """Run one connection to its end; returns (reason, hello was good).

        The thread calls it; a test calls it with a scripted socket.
        """
        self._buf = bytearray()
        announced = False
        try:
            info = self._handshake(sock)
            announced = True
            self._failure_logged = False
            self._recovery.ok(self._clock())
            with self._sock_lock:
                self._connected = True
            _call_sink(sink.on_connected, info)
            reason = self._read_loop(sock, sink)
        except _Closed as exc:
            reason = str(exc)
        finally:
            with self._sock_lock:
                self._connected = False
        if announced:
            _call_sink(sink.on_disconnected, reason)
            LOG.debug("owntone-mini events: connection closed (%s)", reason)
        else:
            self._fail(f"no usable hello from {self._path} ({reason})")
        return reason, announced

    def _handshake(self, sock: "socket.socket") -> ConnectInfo:
        sock.settimeout(HELLO_TIMEOUT_S)
        self._send_checked(sock, {"type": "hello", "protocol": PROTOCOL, "client": self._client})
        try:
            msg = self._read_message(sock)
        except socket.timeout:
            raise _Closed("hello timeout")
        mtype = msg.get("type")
        if mtype == "error":
            raise _Closed("error:" + str(msg.get("code") or "unknown"))
        if mtype != "hello":
            raise _Closed("expected hello")
        if msg.get("protocol") != PROTOCOL:
            raise _Closed("protocol:" + str(msg.get("protocol")))
        boot = msg.get("boot")
        uptime = msg.get("uptime_ms")
        capabilities = msg.get("capabilities")
        return ConnectInfo(
            boot=boot if isinstance(boot, str) and boot else None,
            uptime_ms=uptime if isinstance(uptime, int) and not isinstance(uptime, bool) else None,
            capabilities=frozenset(str(c) for c in capabilities) if isinstance(capabilities, list) else frozenset(),
            kind=self.kind,
        )

    def _read_loop(self, sock: "socket.socket", sink: EventSink) -> str:
        now = self._clock()
        next_ping = now + PING_INTERVAL_S
        last_pong = now
        ping_count = 0
        while not self._stop.is_set():
            now = self._clock()
            if now - last_pong >= PONG_DEADLINE_S:
                LOG.info("owntone-mini events: no pong for %.0f s; reconnecting", now - last_pong)
                return "no pong"
            if now >= next_ping:
                ping_count += 1
                self._send_checked(sock, {"type": "ping", "t": ping_count})
                next_ping = now + PING_INTERVAL_S
            wait = min(next_ping, last_pong + PONG_DEADLINE_S) - now
            sock.settimeout(max(0.05, min(wait, _READ_SLICE_S)))
            try:
                msg = self._read_message(sock)
            except socket.timeout:
                continue
            mtype = msg.get("type")
            if mtype == "changed":
                if msg.get("what") == "outputs":
                    _call_sink(sink.on_outputs_changed)
            elif mtype == "event":
                event = parse_event(msg, self._clock())
                if event is not None:
                    _call_sink(sink.on_device_event, event)
            elif mtype == "pong":
                self.pongs += 1
                last_pong = self._clock()
            elif mtype == "error":
                code = str(msg.get("code") or "unknown")
                LOG.info("owntone-mini events: server error %s (%s)", code, msg.get("text") or "")
                return "error:" + code
            # Any other type is from a newer protocol revision: ignored.
        return "stopped"

    # ------------------------------------------------------------ line I/O

    def _read_message(self, sock: "socket.socket") -> dict:
        """The next JSON object from the server. A line that is not a JSON
        object is skipped. socket.timeout propagates with the buffer kept."""
        while True:
            line = self._read_line(sock)
            try:
                msg = json.loads(line.decode("utf-8", "replace"))
            except ValueError:
                LOG.debug("owntone-mini events: line is not JSON; ignored")
                continue
            if isinstance(msg, dict):
                return msg

    def _read_line(self, sock: "socket.socket") -> bytes:
        while True:
            end = self._buf.find(b"\n")
            if end >= 0:
                line = bytes(self._buf[:end])
                del self._buf[: end + 1]
                if len(line) > MAX_SERVER_LINE:
                    raise _Closed("line too long")
                return line
            if len(self._buf) > MAX_SERVER_LINE:
                raise _Closed("line too long")
            try:
                data = sock.recv(65536)
            except socket.timeout:
                raise
            except OSError as exc:
                raise _Closed(f"read failed: {exc}")
            if not data:
                raise _Closed("closed by the server")
            self._buf += data

    def _send(self, sock: "socket.socket", obj: dict) -> bool:
        try:
            sock.sendall(json.dumps(obj, separators=(",", ":")).encode("utf-8") + b"\n")
        except OSError:
            return False
        return True

    def _send_checked(self, sock: "socket.socket", obj: dict) -> None:
        if not self._send(sock, obj):
            raise _Closed("write failed")


def _connect_unix(path: str) -> "socket.socket":
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        sock.settimeout(HELLO_TIMEOUT_S)
        sock.connect(path)
    except OSError:
        sock.close()
        raise
    return sock


def _close_socket(sock: "socket.socket") -> None:
    try:
        shutdown = getattr(sock, "shutdown", None)
        if shutdown is not None:
            shutdown(socket.SHUT_RDWR)
    except OSError:
        pass
    try:
        sock.close()
    except OSError:
        pass


class PollEventSource(EventSource):
    """No push channel: report "outputs changed" on a timer."""

    kind = "poll"

    def __init__(self, interval: Callable[[], float]) -> None:
        self._interval = interval
        self._sink: Optional[EventSink] = None
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()

    @property
    def connected(self) -> bool:
        thread = self._thread
        return thread is not None and thread.is_alive()

    def start(self, sink: EventSink) -> None:
        if self._thread is not None:
            return
        self._sink = sink
        self._stop.clear()
        _call_sink(sink.on_connected, ConnectInfo(boot=None, uptime_ms=None, capabilities=frozenset(), kind=self.kind))
        self._thread = threading.Thread(target=self._run, name="outputs-events", daemon=True)
        self._thread.start()

    def stop(self, timeout: float = 2.0) -> None:
        self._stop.set()
        thread = self._thread
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout)
        self._thread = None

    def _next_interval(self) -> float:
        try:
            return max(0.05, float(self._interval()))
        except Exception:
            LOG.exception("Poll interval unavailable; using 5 s")
            return 5.0

    def _run(self) -> None:
        while not self._stop.wait(self._next_interval()):
            _call_sink(self._sink.on_outputs_changed)


_websocket_import_logged = False


class WebSocketEventSource(EventSource):
    """Upstream OwnTone's notification websocket, through python3-websocket."""

    kind = "websocket"

    def __init__(
        self,
        url: str,
        *,
        subprotocol: Optional[str],
        import_module: Callable[[str], object] = importlib.import_module,
        backoff: Sequence[float] = _BACKOFF_S,
    ) -> None:
        self._url = url
        self._subprotocol = subprotocol
        self._import = import_module
        self._backoff = tuple(backoff) or _BACKOFF_S
        self._sink: Optional[EventSink] = None
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self._lock = threading.Lock()  # leaf: guards _app and _connected
        self._app = None
        self._connected = False
        self.degraded = False

    @property
    def connected(self) -> bool:
        with self._lock:
            return self._connected

    def start(self, sink: EventSink) -> None:
        global _websocket_import_logged
        if self._thread is not None:
            return
        self._sink = sink
        try:
            module = self._import("websocket")
        except ImportError:
            if not _websocket_import_logged:
                _websocket_import_logged = True
                LOG.info("python3-websocket not installed; polling the player instead")
            self._degrade()
            return
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._run, args=(module,), name="outputs-events", daemon=True
        )
        self._thread.start()

    def stop(self, timeout: float = 2.0) -> None:
        self._stop.set()
        with self._lock:
            app = self._app
        if app is not None:
            try:
                app.close()
            except Exception:
                pass
        thread = self._thread
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout)
        self._thread = None

    def _degrade(self) -> None:
        self.degraded = True
        _call_sink(self._sink.on_disconnected, DEGRADED)

    def _run(self, module) -> None:
        failures = 0
        while not self._stop.is_set():
            opened = self.run_connection(module)
            if self._stop.is_set():
                return
            failures = 0 if opened else failures + 1
            if failures >= WEBSOCKET_FAILURES_BEFORE_DEGRADED:
                LOG.info("Player websocket unavailable after %d attempts; polling instead", failures)
                self._degrade()
                return
            self._stop.wait(self._backoff[min(max(failures - 1, 0), len(self._backoff) - 1)])

    def run_connection(self, module) -> bool:
        """One connection attempt to its end; True when the socket opened."""
        opened = False

        def on_open(ws) -> None:
            nonlocal opened
            opened = True
            with self._lock:
                self._connected = True
            try:
                ws.send(json.dumps({"notify": _WEBSOCKET_NOTIFY}))
            except Exception as exc:
                LOG.debug("Player websocket subscription failed: %s", exc)
            _call_sink(
                self._sink.on_connected,
                ConnectInfo(boot=None, uptime_ms=None, capabilities=frozenset(), kind=self.kind),
            )

        def on_message(ws, message) -> None:
            _call_sink(self._sink.on_outputs_changed)

        def on_error(ws, error) -> None:
            LOG.debug("Player websocket error: %s", error)

        app = module.WebSocketApp(
            self._url,
            subprotocols=[self._subprotocol] if self._subprotocol else None,
            on_open=on_open,
            on_message=on_message,
            on_error=on_error,
        )
        with self._lock:
            self._app = app
        try:
            app.run_forever(ping_interval=30, ping_timeout=10)
        except Exception as exc:
            LOG.debug("Player websocket ended: %s", exc)
        finally:
            with self._lock:
                self._app = None
                was_connected = self._connected
                self._connected = False
        if opened and was_connected:
            _call_sink(self._sink.on_disconnected, "closed")
        return opened


def create_event_source(
    info: EventChannelInfo,
    base_url: str,
    *,
    poll_interval: Callable[[], float],
) -> EventSource:
    """The source an event channel description calls for.

    A description that cannot be used (a socket without a path, a channel
    nobody answered for) gives the polling source.
    """
    if info.kind == "unix_socket" and info.socket_path and info.reachable:
        return UnixSocketEventSource(info.socket_path, client_name=CLIENT_NAME)
    if info.kind == "websocket" and info.reachable:
        parsed = urlparse(base_url)
        host = parsed.hostname or "localhost"
        if ":" in host:
            host = f"[{host}]"
        if info.websocket_port:
            return WebSocketEventSource(f"ws://{host}:{info.websocket_port}", subprotocol="notify")
        port = parsed.port or 80
        return WebSocketEventSource(f"ws://{host}:{port}/ws", subprotocol=None)
    return PollEventSource(poll_interval)
