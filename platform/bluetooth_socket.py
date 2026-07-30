#!/usr/bin/python3
"""bluetooth_socket.py

Copyright (c) 2026 Lo-tech Systems Limited. All rights reserved.

Unix-domain socket JSON control API for the autostream_bluetooth daemon.
One JSON request per connection, one JSON
reply; same trust model as the monitor's control socket (filesystem
permissions on ``/run/autostream-bluetooth/bluetooth.sock``, mode 0660) — the
PIN-gated webui process is the sole client. The socket lives in its own
RuntimeDirectory (rather than the shared ``/run/autostream``) so the unit
never needs to chown/touch a directory another service owns.

Structure mirrors ``dial/dial_control.py`` (ThreadingMixIn over a Unix
stream server, a pure ``dispatch()`` parse/validate/route function callable
without a real socket, MAC validated server-side on ``pair``). The exact
request/reply shapes below are the pinned contract the webui client
(``core/autostream_bluetooth_client.py``, owned separately) is written
against — do not change field names without updating that client. Status
additionally reports the configured audio buffer (``buffer_ms``) and the
selected adapter's bus kind (``adapter_kind``); ``configure`` sets a new
audio buffer, range-validated server-side exactly like ``pair``'s MAC.
"""
from __future__ import annotations

import json
import logging
import os
import re
import socket
import socketserver
import stat
import threading
from typing import Callable, Optional

logger = logging.getLogger(__name__)

DEFAULT_SOCKET_PATH = "/run/autostream-bluetooth/bluetooth.sock"
SOCKET_MODE = 0o660
REQUEST_MAX_BYTES = 4096
CLIENT_TIMEOUT = 2.0

MAC_RE = re.compile(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")

_AF_UNIX = getattr(socket, "AF_UNIX", None)


class _UnixStreamServer(socketserver.TCPServer):
    address_family = _AF_UNIX if _AF_UNIX is not None else socket.AF_INET


class _ThreadingUnixStreamServer(socketserver.ThreadingMixIn, _UnixStreamServer):
    daemon_threads = True


# cmd -> allowed request keys (including "cmd" itself).
_ALLOWED_KEYS: dict[str, frozenset] = {
    "status":       frozenset({"cmd"}),
    "scan_start":   frozenset({"cmd"}),
    "scan_stop":    frozenset({"cmd"}),
    "scan_results": frozenset({"cmd"}),
    "pair":         frozenset({"cmd", "mac"}),
    "pair_status":  frozenset({"cmd"}),
    "forget":       frozenset({"cmd"}),
    "configure":    frozenset({"cmd", "buffer_ms"}),
}

# Default surfaced when a server implementation predates buffer_ms (kept in
# sync with bluetooth_service.DEFAULT_BUFFER_MS; not imported to avoid a
# cycle — this module has no dependency on the state-machine layer).
_DEFAULT_BUFFER_MS = 200

# Default surfaced when a server implementation predates the version key
# (kept in sync with bluetooth_service.BLUETOOTH_SERVICE_VERSION; not
# imported for the same reason as _DEFAULT_BUFFER_MS above).
_DEFAULT_VERSION = "0.5.1"


def _ok(**kwargs) -> dict:
    return {"ok": True, **kwargs}


def _err(error: str) -> dict:
    return {"ok": False, "error": error}


# ---------------------------------------------------------------------------
# Request handler
# ---------------------------------------------------------------------------

class _ControlHandler(socketserver.BaseRequestHandler):
    """Handle one client connection: read one request, send one response."""

    def handle(self) -> None:
        server: BluetoothControlServer = self.server.bluetooth_control_server  # type: ignore[attr-defined]
        conn: socket.socket = self.request

        try:
            conn.settimeout(CLIENT_TIMEOUT)
        except OSError:
            return

        buf = b""
        try:
            while True:
                chunk = conn.recv(256)
                if not chunk:
                    break  # client disconnected
                buf += chunk
                if b"\n" in buf:
                    break
                if len(buf) > REQUEST_MAX_BYTES:
                    break
        except (OSError, TimeoutError):
            return

        response = dispatch(buf, server)
        try:
            line = json.dumps(response, separators=(",", ":")) + "\n"
            conn.sendall(line.encode("utf-8"))
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass


def dispatch(raw: bytes, server: "BluetoothControlServer") -> dict:
    """Parse one newline-delimited JSON request and dispatch it.

    Pure apart from calling into *server*'s injected callables, so it is
    directly unit-testable against a fake server without a real socket
    (mirrors ``dial_control._dispatch``).
    """
    if len(raw) > REQUEST_MAX_BYTES and b"\n" not in raw[:REQUEST_MAX_BYTES + 1]:
        return _err("request_too_large")

    newline_pos = raw.find(b"\n")
    if newline_pos < 0:
        return _err("invalid_request")
    if newline_pos >= REQUEST_MAX_BYTES:
        return _err("request_too_large")

    line = raw[:newline_pos]
    tail = raw[newline_pos + 1:]
    if tail.strip():
        return _err("invalid_request")

    try:
        text = line.decode("utf-8")
    except UnicodeDecodeError:
        return _err("invalid_json")

    try:
        obj = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return _err("invalid_json")

    if not isinstance(obj, dict):
        return _err("invalid_request")

    cmd = obj.get("cmd")
    if not isinstance(cmd, str):
        return _err("invalid_request")
    if cmd not in _ALLOWED_KEYS:
        return _err("unknown_cmd")

    allowed = _ALLOWED_KEYS[cmd]
    extra = sorted(k for k in obj if k not in allowed)
    if extra:
        return _err("unexpected_field")

    try:
        if cmd == "status":
            return _handle_status(server)
        if cmd == "scan_start":
            if not server.scan_start():
                return _err("scan_in_progress")
            return _ok()
        if cmd == "scan_stop":
            server.scan_stop()
            return _ok()
        if cmd == "scan_results":
            return _ok(devices=server.get_scan_results())
        if cmd == "pair":
            return _handle_pair(obj, server)
        if cmd == "pair_status":
            return _handle_pair_status(server)
        if cmd == "forget":
            server.forget()
            return _ok()
        if cmd == "configure":
            return _handle_configure(obj, server)
    except Exception:
        logger.exception("bluetooth control: internal error handling cmd %r", cmd)
        return _err("internal_error")

    return _err("unknown_cmd")


def _handle_status(server: "BluetoothControlServer") -> dict:
    st = server.get_status()
    reply = _ok(
        adapter_present=bool(st.get("adapter_present", False)),
        paired=st.get("paired"),
        link=st.get("link", "disconnected"),
        streaming=bool(st.get("streaming", False)),
        scanning=bool(st.get("scanning", False)),
        pump_source_active=bool(st.get("pump_source_active", False)),
        loopback_held=bool(st.get("loopback_held", False)),
        buffer_ms=int(st.get("buffer_ms", _DEFAULT_BUFFER_MS)),
        adapter_kind=st.get("adapter_kind"),
        adapter_blocked=bool(st.get("adapter_blocked", False)),
        version=str(st.get("version") or _DEFAULT_VERSION),
    )
    # Transport-conditional fields: the daemon includes these only while an
    # A2DP transport is active (the negotiated codec name and sample rate),
    # so the wire envelope forwards them on the same terms rather than
    # inventing placeholder values for the idle case.
    for key in ("codec", "sample_rate"):
        if key in st:
            reply[key] = st[key]
    return reply


def _handle_pair(obj: dict, server: "BluetoothControlServer") -> dict:
    mac = obj.get("mac")
    if not isinstance(mac, str) or not MAC_RE.match(mac):
        return _err("invalid_mac")
    # server.pair() (BluetoothStateMachine.start_pairing) returns False when
    # a pairing attempt is already in flight; that must reach the client as
    # a distinct error rather than a silent success.
    # This exact string is pinned: the webui maps it to HTTP 409.
    if not server.pair(mac):
        return _err("pair_in_progress")
    return _ok()


def _handle_configure(obj: dict, server: "BluetoothControlServer") -> dict:
    buffer_ms = obj.get("buffer_ms")
    # Type-shape check here (mirrors the MAC-regex check in _handle_pair());
    # the 100..500 range validation is delegated to server.configure() so
    # both failure modes map to the one pinned error string.
    if not isinstance(buffer_ms, int) or isinstance(buffer_ms, bool):
        return _err("invalid_buffer_ms")
    if not server.configure(buffer_ms):
        return _err("invalid_buffer_ms")
    return _ok()


def _handle_pair_status(server: "BluetoothControlServer") -> dict:
    st = server.get_pair_status()
    resp = _ok(state=st.get("state", "idle"))
    if st.get("error"):
        resp["error"] = st["error"]
    return resp


# ---------------------------------------------------------------------------
# BluetoothControlServer
# ---------------------------------------------------------------------------

class BluetoothControlServer:
    """Unix-domain socket control API for the running autostream_bluetooth
    daemon. Callbacks are injected so the socket/protocol layer has no direct
    dependency on the state machine or bluez client.

    Parameters
    ----------
    get_status: () -> dict with adapter_present, paired ({mac,name}|None),
        link, streaming, scanning, pump_source_active, buffer_ms,
        adapter_kind ("usb"|"onboard"|"unknown"|None), version (daemon
        version string).
    scan_start: () -> bool — False when a pairing attempt is already in
        flight (reported to the client as {"ok":false,"error":"scan_in_progress"}).
    scan_stop: () -> None.
    get_scan_results: () -> list[dict] ({mac, name, rssi, paired}).
    pair: (mac: str) -> bool — async; True once accepted (caller polls
        get_pair_status), False when a pairing attempt is already in flight
        (reported to the client as {"ok":false,"error":"pair_in_progress"} —
        this exact string is pinned; the webui maps it to HTTP 409).
    get_pair_status: () -> dict with state (idle|pairing|done|failed) and
        optional error.
    forget: () -> None.
    configure: (buffer_ms: int) -> bool — True once the new audio buffer
        (milliseconds, 100..500 inclusive) is accepted and persisted, False
        for an out-of-range value (reported to the client as
        {"ok":false,"error":"invalid_buffer_ms"} — this exact string is
        pinned).
    socket_path: Unix socket path; defaults to DEFAULT_SOCKET_PATH.
    """

    def __init__(
        self,
        *,
        get_status: Callable[[], dict],
        scan_start: Callable[[], bool],
        scan_stop: Callable[[], None],
        get_scan_results: Callable[[], list],
        pair: Callable[[str], bool],
        get_pair_status: Callable[[], dict],
        forget: Callable[[], None],
        configure: Callable[[int], bool],
        socket_path: str = DEFAULT_SOCKET_PATH,
    ) -> None:
        self.get_status = get_status
        self.scan_start = scan_start
        self.scan_stop = scan_stop
        self.get_scan_results = get_scan_results
        self.pair = pair
        self.get_pair_status = get_pair_status
        self.forget = forget
        self.configure = configure
        self.socket_path = socket_path

        self._server: Optional[_ThreadingUnixStreamServer] = None
        self._thread: Optional[threading.Thread] = None
        self._started = False
        self._stopped = False
        self._lock = threading.Lock()
        # Device + inode recorded after bind for safe unlink on shutdown.
        self._sock_dev: Optional[int] = None
        self._sock_ino: Optional[int] = None

    def start(self) -> None:
        """Bind the socket and start the server thread.

        Raises RuntimeError if called more than once, or if AF_UNIX is
        absent. Raises OSError if the socket path already exists as a
        non-socket file.
        """
        if _AF_UNIX is None:
            raise RuntimeError(
                "AF_UNIX is not available on this platform; "
                "the bluetooth control socket requires a Unix socket"
            )

        with self._lock:
            if self._started:
                raise RuntimeError("BluetoothControlServer.start() called twice")
            self._started = True

        path = self.socket_path
        directory = os.path.dirname(path) or "."
        os.makedirs(directory, exist_ok=True)

        # Stale socket cleanup: remove only an existing Unix socket.
        try:
            st = os.lstat(path)
            if stat.S_ISSOCK(st.st_mode):
                os.unlink(path)
                logger.info("bluetooth control: removed stale socket %s", path)
            else:
                raise OSError(f"bluetooth control: path exists and is not a socket: {path!r}")
        except FileNotFoundError:
            pass

        # bind() creates the socket file honouring the process umask, and a
        # chmod() immediately after bind() leaves a window (however small)
        # where the socket exists at the wrong mode (TOCTOU). Narrow that
        # window to zero by setting a umask that
        # produces SOCKET_MODE directly for the bind's own creation; the
        # chmod below is kept as belt-and-braces in case umask handling ever
        # differs across platforms/socket implementations.
        prior_umask = os.umask(0o117)  # 0o777 & ~0o660 == 0o117
        try:
            server = _ThreadingUnixStreamServer(path, _ControlHandler)
        finally:
            os.umask(prior_umask)
        server.bluetooth_control_server = self  # type: ignore[attr-defined]

        # Belt-and-braces: apply the explicit mode in case the umask above
        # did not fully determine it (e.g. an already-existing path reused).
        try:
            os.chmod(path, SOCKET_MODE)
        except OSError as e:
            logger.warning("bluetooth control: chmod %s failed: %s", path, e)

        try:
            st2 = os.stat(path)
            self._sock_dev = st2.st_dev
            self._sock_ino = st2.st_ino
        except OSError:
            pass

        self._server = server

        t = threading.Thread(
            target=server.serve_forever,
            kwargs={"poll_interval": 0.1},
            daemon=True,
            name="bt-control",
        )
        self._thread = t
        t.start()
        logger.info("bluetooth control: listening on %s", path)

    def stop(self) -> None:
        """Shut down the server and remove the socket file. Safe to call
        before start() and idempotent after stop()."""
        with self._lock:
            if self._stopped:
                return
            self._stopped = True

        server = self._server
        if server is None:
            return

        try:
            server.shutdown()
            server.server_close()
        except Exception as e:
            logger.warning("bluetooth control: error during shutdown: %s", e)

        self._unlink_socket()

    def _unlink_socket(self) -> None:
        """Remove the socket only when it is still our socket (same device +
        inode) — a replaced/stale socket at the same path is left alone."""
        path = self.socket_path
        try:
            st = os.lstat(path)
            if not stat.S_ISSOCK(st.st_mode):
                return
            if self._sock_dev is not None and self._sock_ino is not None:
                if st.st_dev != self._sock_dev or st.st_ino != self._sock_ino:
                    logger.debug(
                        "bluetooth control: socket at %s was replaced; not removing", path
                    )
                    return
            os.unlink(path)
            logger.info("bluetooth control: removed socket %s", path)
        except FileNotFoundError:
            pass
        except OSError as e:
            logger.warning("bluetooth control: could not remove socket %s: %s", path, e)
