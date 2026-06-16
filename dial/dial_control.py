"""dial_control.py — Unix-domain socket control server for autostream-dial.

Exposes a local newline-delimited JSON protocol so operators can exercise the
running dial's live volume path over SSH without a physical rotary encoder.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

import json
import logging
import os
import socket
import socketserver
import stat
import threading
from typing import Callable

from dial_control_protocol import (
    CONTROL_PROTOCOL_NAME,
    CONTROL_PROTOCOL_VERSION,
    CONTROL_REQUEST_MAX_BYTES,
    CONTROL_SERVER_CLIENT_TIMEOUT,
    CONTROL_SOCKET_PATH,
)

# ---------------------------------------------------------------------------
# AF_UNIX shim — absent from some Python builds and from Windows
# ---------------------------------------------------------------------------

_AF_UNIX = getattr(socket, "AF_UNIX", None)


class _UnixStreamServer(socketserver.TCPServer):
    address_family = _AF_UNIX if _AF_UNIX is not None else socket.AF_INET


class _ThreadingUnixStreamServer(
    socketserver.ThreadingMixIn,
    _UnixStreamServer,
):
    daemon_threads = True


# ---------------------------------------------------------------------------
# Protocol helpers
# ---------------------------------------------------------------------------

_ALLOWED_KEYS: dict[str, frozenset] = {
    "ping":    frozenset({"command"}),
    "version": frozenset({"command"}),
    "status":  frozenset({"command"}),
    "targets": frozenset({"command"}),
    "nudge":   frozenset({"command", "direction", "delta"}),
}


def _ok(**kwargs) -> dict:
    return {"ok": True, **kwargs}


def _err(error: str, message: str) -> dict:
    return {"ok": False, "error": error, "message": message}


# ---------------------------------------------------------------------------
# Request handler
# ---------------------------------------------------------------------------

class _ControlHandler(socketserver.BaseRequestHandler):
    """Handle one client connection: read one request, send one response."""

    def handle(self) -> None:
        server: DialControlServer = self.server.dial_control_server  # type: ignore[attr-defined]
        conn: socket.socket = self.request

        try:
            conn.settimeout(CONTROL_SERVER_CLIENT_TIMEOUT)
        except OSError:
            return

        # Read up to MAX+1 bytes looking for a newline
        buf = b""
        try:
            while True:
                chunk = conn.recv(256)
                if not chunk:
                    break  # client disconnected
                buf += chunk
                if b"\n" in buf:
                    break
                if len(buf) > CONTROL_REQUEST_MAX_BYTES:
                    break
        except (OSError, TimeoutError):
            return

        response = _dispatch(buf, server)
        try:
            line = json.dumps(response, separators=(",", ":"), sort_keys=False) + "\n"
            conn.sendall(line.encode("utf-8"))
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass


def _dispatch(raw: bytes, server: "DialControlServer") -> dict:
    """Parse raw bytes and dispatch to the appropriate handler."""
    # --- Framing checks ---
    if len(raw) > CONTROL_REQUEST_MAX_BYTES and b"\n" not in raw[:CONTROL_REQUEST_MAX_BYTES + 1]:
        return _err("request_too_large",
                    f"request exceeds {CONTROL_REQUEST_MAX_BYTES} bytes")

    newline_pos = raw.find(b"\n")
    if newline_pos < 0:
        return _err("invalid_request", "request must end with a newline")

    line = raw[:newline_pos]

    # Check for trailing non-whitespace data after the first newline
    tail = raw[newline_pos + 1:]
    if tail.strip():
        return _err("invalid_request", "trailing data after request")

    # Reject if the line itself is too long (newline is beyond the limit)
    if newline_pos >= CONTROL_REQUEST_MAX_BYTES:
        return _err("request_too_large",
                    f"request exceeds {CONTROL_REQUEST_MAX_BYTES} bytes")

    # --- UTF-8 + JSON parse ---
    try:
        text = line.decode("utf-8")
    except UnicodeDecodeError:
        return _err("invalid_json", "request is not valid UTF-8")

    try:
        obj = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return _err("invalid_json", "request is not valid JSON")

    if not isinstance(obj, dict):
        return _err("invalid_request", "request must be a JSON object")

    # --- Command dispatch ---
    cmd = obj.get("command")
    if not isinstance(cmd, str):
        return _err("invalid_request", "command must be a string")

    if cmd not in _ALLOWED_KEYS:
        return _err("unknown_command", f"unknown command: {cmd}")

    allowed = _ALLOWED_KEYS[cmd]
    extra = sorted(k for k in obj if k not in allowed)
    if extra:
        return _err("unexpected_field", f"unexpected field: {extra[0]}")

    try:
        if cmd == "ping":
            return _handle_ping()
        elif cmd == "version":
            return _handle_version(server)
        elif cmd == "status":
            return _handle_status(server)
        elif cmd == "targets":
            return _handle_targets(server)
        elif cmd == "nudge":
            return _handle_nudge(obj, server)
    except Exception:
        logging.exception("dial control: internal error handling command %r", cmd)
        return _err("internal_error", "an unexpected error occurred")

    return _err("unknown_command", f"unknown command: {cmd}")


def _handle_ping() -> dict:
    return _ok(service="autostream-dial")


def _handle_version(server: "DialControlServer") -> dict:
    return _ok(
        protocol=CONTROL_PROTOCOL_NAME,
        protocol_version=CONTROL_PROTOCOL_VERSION,
        software_version=server.software_version,
    )


def _handle_status(server: "DialControlServer") -> dict:
    status = server.get_runtime_status()
    targets = server.get_targets()
    return _ok(
        uuid=status["uuid"],
        name=status["name"],
        step_percent=status["step_percent"],
        target_count=len(targets),
        recovery_active=status["recovery_active"],
        volume_confirmed=status["volume_confirmed"],
    )


def _handle_targets(server: "DialControlServer") -> dict:
    status = server.get_runtime_status()
    dial_id = status["uuid"]
    targets = server.get_targets()
    enriched = server.enrich_targets(targets, dial_id)
    return _ok(count=len(enriched), targets=enriched)


def _handle_nudge(obj: dict, server: "DialControlServer") -> dict:
    has_direction = "direction" in obj
    has_delta = "delta" in obj

    if has_direction and has_delta:
        return _err("invalid_request",
                    "specify either direction or delta, not both")

    if not has_direction and not has_delta:
        return _err("invalid_request",
                    "nudge requires either direction or delta")

    if has_direction:
        direction = obj["direction"]
        if direction not in ("up", "down"):
            return _err("invalid_direction",
                        "direction must be 'up' or 'down'")
        targets_before = server.get_targets()
        if direction == "up":
            delta = server.nudge_up()
        else:
            delta = server.nudge_down()
    else:
        raw_delta = obj["delta"]
        if isinstance(raw_delta, bool) or not isinstance(raw_delta, int):
            return _err("invalid_delta",
                        "delta must be an integer from -100 to 100 excluding zero")
        if raw_delta == 0 or not (-100 <= raw_delta <= 100):
            return _err("invalid_delta",
                        "delta must be an integer from -100 to 100 excluding zero")
        targets_before = server.get_targets()
        delta = server.nudge_delta(raw_delta)

    return _ok(
        queued=True,
        delta=delta,
        target_count=len(targets_before),
    )


# ---------------------------------------------------------------------------
# DialControlServer
# ---------------------------------------------------------------------------

class DialControlServer:
    """Unix-domain socket control server for the running autostream-dial service.

    Parameters
    ----------
    get_runtime_status:
        Callable returning a dict with uuid, name, step_percent,
        recovery_active, volume_confirmed.
    get_targets:
        Callable returning a list of PlayingTarget objects.
    enrich_targets:
        Callable(targets, dial_id) -> list[dict].
    nudge_up, nudge_down, nudge_delta:
        Shared action callables (same instances passed to the GPIO encoder).
    software_version:
        Value from dial_http_server.VERSION.
    socket_path:
        Unix socket path; defaults to CONTROL_SOCKET_PATH.
    """

    def __init__(
        self,
        *,
        get_runtime_status: Callable,
        get_targets: Callable,
        enrich_targets: Callable,
        nudge_up: Callable,
        nudge_down: Callable,
        nudge_delta: Callable,
        software_version: str,
        socket_path: str = CONTROL_SOCKET_PATH,
    ) -> None:
        self.get_runtime_status = get_runtime_status
        self.get_targets = get_targets
        self.enrich_targets = enrich_targets
        self.nudge_up = nudge_up
        self.nudge_down = nudge_down
        self.nudge_delta = nudge_delta
        self.software_version = software_version
        self.socket_path = socket_path

        self._server: _ThreadingUnixStreamServer | None = None
        self._thread: threading.Thread | None = None
        self._started = False
        self._stopped = False
        self._lock = threading.Lock()
        # Device + inode recorded after bind for safe unlink
        self._sock_dev: int | None = None
        self._sock_ino: int | None = None

    def start(self) -> None:
        """Bind the socket and start the server thread.

        Raises RuntimeError if called more than once, or if AF_UNIX is absent.
        Raises OSError if the socket path already exists as a non-socket file.
        """
        if _AF_UNIX is None:
            raise RuntimeError(
                "AF_UNIX is not available on this platform; "
                "dial control socket requires a Unix socket"
            )

        with self._lock:
            if self._started:
                raise RuntimeError("DialControlServer.start() called twice")
            self._started = True

        path = self.socket_path

        # Stale socket cleanup: remove only an existing Unix socket
        try:
            st = os.lstat(path)
            if stat.S_ISSOCK(st.st_mode):
                os.unlink(path)
                logging.info("dial control: removed stale socket %s", path)
            else:
                raise OSError(
                    f"dial control: path exists and is not a socket: {path!r}"
                )
        except FileNotFoundError:
            pass  # path does not exist — that's fine

        server = _ThreadingUnixStreamServer(path, _ControlHandler)
        server.dial_control_server = self  # type: ignore[attr-defined]

        # Apply explicit socket mode (bind respects umask, not desired mode)
        try:
            os.chmod(path, 0o660)
        except OSError as e:
            logging.warning("dial control: chmod %s failed: %s", path, e)

        # Record device + inode for safe unlink on shutdown
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
            name="dial-control",
        )
        self._thread = t
        t.start()
        logging.info("dial control: listening on %s", path)

    def stop(self) -> None:
        """Shut down the server and remove the socket file.  Safe to call before
        start() and idempotent after stop()."""
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
            logging.warning("dial control: error during shutdown: %s", e)

        self._unlink_socket()

    def _unlink_socket(self) -> None:
        """Remove the socket only when it is still our socket (same device + inode)."""
        path = self.socket_path
        try:
            st = os.lstat(path)
            if not stat.S_ISSOCK(st.st_mode):
                return
            if self._sock_dev is not None and self._sock_ino is not None:
                if st.st_dev != self._sock_dev or st.st_ino != self._sock_ino:
                    logging.debug(
                        "dial control: socket at %s was replaced; not removing", path
                    )
                    return
            os.unlink(path)
            logging.info("dial control: removed socket %s", path)
        except FileNotFoundError:
            pass
        except OSError as e:
            logging.warning("dial control: could not remove socket %s: %s", path, e)
