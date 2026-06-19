"""track_id.vibra_client — IPC client for the vibra-mini daemon."""
from __future__ import annotations

import json
import logging
import socket
import threading
from typing import Optional

_log = logging.getLogger(__name__)


class VibraClient:
    """Unix domain socket client for the vibra-mini Shazam daemon.

    Mirrors MonitorClient in structure: one connection, internal lock,
    reconnect-and-retry-once on socket/EOF/timeout failure.

    Thread-safe.  The lock serialises concurrent recognize() calls so the
    daemon (which handles one client at a time) is never sent interleaved
    requests.
    """

    DEFAULT_SOCKET_PATH = "/tmp/vibra-mini.sock"
    COMMAND_TIMEOUT = 15.0  # seconds; covers Shazam HTTP + fingerprint + round-trip

    def __init__(self, socket_path: str = DEFAULT_SOCKET_PATH) -> None:
        self._socket_path = socket_path
        self._sock: Optional[socket.socket] = None
        self._recv_buf = b""
        self._lock = threading.Lock()

    # ── Connection management ────────────────────────────────────────────────

    def connect(self) -> bool:
        """Open the Unix domain socket to the daemon.

        Returns True on success.  Logs and returns False on failure.
        Closes any existing connection first.
        """
        self.close()
        try:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.settimeout(self.COMMAND_TIMEOUT)
            sock.connect(self._socket_path)
            self._sock = sock
            return True
        except OSError as exc:
            _log.warning("vibra: connect to %s failed: %s", self._socket_path, exc)
            return False

    def close(self) -> None:
        """Close the connection and discard the receive buffer."""
        sock = self._sock
        self._sock = None
        self._recv_buf = b""
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass

    def is_connected(self) -> bool:
        return self._sock is not None

    # ── Low-level I/O ────────────────────────────────────────────────────────

    def _readline(self) -> Optional[bytes]:
        """Read one newline-terminated line, stripping the newline.

        Returns None on EOF or socket error, closing the connection.
        """
        while True:
            nl = self._recv_buf.find(b"\n")
            if nl >= 0:
                line = self._recv_buf[:nl]
                self._recv_buf = self._recv_buf[nl + 1:]
                return line
            try:
                chunk = self._sock.recv(4096)
            except OSError:
                self.close()
                return None
            if not chunk:
                self.close()
                return None
            self._recv_buf += chunk

    def _sendall(self, data: bytes) -> bool:
        """Send all bytes; close and return False on error."""
        try:
            self._sock.sendall(data)
            return True
        except OSError:
            self.close()
            return False

    def _read_response(self) -> Optional[dict]:
        """Read and parse one JSON response line.

        Returns None on EOF, socket error, or invalid JSON, closing the
        connection so the caller's retry logic triggers reconnection.
        """
        line = self._readline()
        if line is None:
            return None
        try:
            obj = json.loads(line)
            if not isinstance(obj, dict):
                self.close()
                return None
            return obj
        except (json.JSONDecodeError, ValueError):
            self.close()
            return None

    # ── Protocol commands ────────────────────────────────────────────────────

    def ping(self) -> dict:
        """Send a ping and return the pong response dict.

        Must be called while holding the lock or from a single-threaded
        context (tests).  Raises OSError if not connected or I/O fails.
        """
        if not self._sock:
            raise OSError("not connected")
        req = (json.dumps({"type": "ping"}, separators=(",", ":")) + "\n").encode()
        if not self._sendall(req):
            raise OSError("vibra: send failed on ping")
        resp = self._read_response()
        if resp is None:
            raise OSError("vibra: no response to ping")
        return resp

    def recognize(self, pcm16_mono: bytes, rate: int = 16000) -> dict:
        """Send PCM to the daemon and return the parsed JSON response dict.

        Connects lazily on first call.  Reconnects and retries once on
        EOF/socket/timeout failure before raising.

        Args:
            pcm16_mono: Raw signed 16-bit little-endian mono PCM bytes.
            rate: Sample rate in Hz (must be 16000 in this protocol version).

        Returns:
            Parsed response dict.  Caller checks 'ok' and 'matched' fields.

        Raises:
            OSError: Connection or I/O failure after exhausting the single retry.
        """
        with self._lock:
            return self._recognize_with_retry(pcm16_mono, rate)

    def _recognize_with_retry(self, pcm16_mono: bytes, rate: int) -> dict:
        for attempt in range(2):
            if not self.is_connected():
                if not self.connect():
                    if attempt == 0:
                        _log.debug("vibra: connect failed; retrying once")
                        continue
                    raise OSError(
                        f"vibra: cannot connect to daemon at {self._socket_path}"
                    )
            try:
                return self._do_recognize(pcm16_mono, rate)
            except OSError:
                self.close()
                if attempt == 0:
                    _log.debug("vibra: socket error; reconnecting and retrying recognize")
                    continue
                raise

    def _do_recognize(self, pcm16_mono: bytes, rate: int) -> dict:
        frames = len(pcm16_mono) // 2  # s16le: 2 bytes per mono frame
        req_obj = {
            "type": "recognize",
            "frames": frames,
            "rate": rate,
            "channels": 1,
            "bits": 16,
        }
        req_line = (json.dumps(req_obj, separators=(",", ":")) + "\n").encode()
        # Send JSON header and binary payload together to avoid extra round-trips.
        if not self._sendall(req_line + pcm16_mono):
            raise OSError("vibra: send failed on recognize")
        resp = self._read_response()
        if resp is None:
            raise OSError("vibra: no response from daemon")
        return resp
