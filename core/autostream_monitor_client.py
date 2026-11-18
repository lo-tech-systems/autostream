"""autostream_monitor_client.py -- client for the autostream_monitor daemon.

A leaf module (standard library and the configuration module): the
Unix-socket client the coordinator and the Web UI use to talk to the native
audio monitor, the socket path lookup, and a context manager that yields a
connected client for one-shot commands.
"""

import contextlib
import json
import logging
import os
import socket
import threading
from typing import Optional

from autostream_config import normalize_log_level


class MonitorClient:
    """Thin wrapper around the autostream_monitor Unix domain socket.

    All commands are synchronous and serialised by _lock so that callers
    on different threads (e.g. the coordinator loop and a background
    recognition thread) do not interleave their JSON lines.

    The client holds a persistent connection.  If the socket is lost,
    is_connected() returns False and the caller is responsible for calling
    connect() again (the coordinator loop does this automatically).
    """

    DEFAULT_SOCKET_PATH = "/tmp/autostream_monitor.sock"
    CONNECT_TIMEOUT = 5.0    # seconds
    COMMAND_TIMEOUT = 15.0   # seconds; covers get_id_snapshot binary transfer

    def __init__(self, socket_path: str = DEFAULT_SOCKET_PATH) -> None:
        self._socket_path = socket_path
        self._sock: Optional[socket.socket] = None
        self._lock = threading.Lock()
        self._recv_buf = b""

    # ── Connection ───────────────────────────────────────────────────────────

    def connect(self) -> bool:
        """Open the socket; return True on success."""
        self.close()
        try:
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.settimeout(self.CONNECT_TIMEOUT)
            s.connect(self._socket_path)
            s.settimeout(self.COMMAND_TIMEOUT)
            self._sock = s
            self._recv_buf = b""
            logging.debug("MonitorClient: connected to %s", self._socket_path)
            return True
        except OSError as e:
            logging.error("MonitorClient: connect failed: %s", e)
            return False

    def close(self) -> None:
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None
        self._recv_buf = b""

    def is_connected(self) -> bool:
        return self._sock is not None

    # ── Low-level I/O ────────────────────────────────────────────────────────

    def _readline(self) -> Optional[bytes]:
        """Read bytes from the socket up to and including the next newline."""
        while b"\n" not in self._recv_buf:
            try:
                chunk = self._sock.recv(4096)
            except OSError:
                self.close()
                return None
            if not chunk:
                self.close()
                return None
            self._recv_buf += chunk
        idx = self._recv_buf.index(b"\n")
        line = self._recv_buf[:idx]
        self._recv_buf = self._recv_buf[idx + 1:]
        return line

    def _readbytes(self, n: int) -> Optional[bytes]:
        """Read exactly n bytes from the socket (used for binary payloads)."""
        while len(self._recv_buf) < n:
            try:
                chunk = self._sock.recv(65536)
            except OSError:
                self.close()
                return None
            if not chunk:
                self.close()
                return None
            self._recv_buf += chunk
        data = self._recv_buf[:n]
        self._recv_buf = self._recv_buf[n:]
        return data

    def _command(self, cmd: dict) -> Optional[dict]:
        """Send one JSON command and return the parsed response dict."""
        if not self._sock:
            return None
        try:
            self._sock.sendall((json.dumps(cmd) + "\n").encode())
            line = self._readline()
            if line is None:
                return None
            parsed = json.loads(line)
            if not isinstance(parsed, dict):
                logging.warning(
                    "MonitorClient: command %r returned non-object response",
                    cmd.get("type"),
                )
                self.close()
                return None
            return parsed
        except (OSError, json.JSONDecodeError, ValueError) as e:
            logging.warning("MonitorClient: command %r failed: %s", cmd.get("type"), e)
            self.close()
            return None

    # ── Commands ─────────────────────────────────────────────────────────────

    def list_devices(self) -> Optional[list[dict]]:
        with self._lock:
            resp = self._command({"type": "list_devices"})
            return resp.get("devices") if resp and resp.get("ok") else None

    def configure_input(
        self,
        index: int,
        device: str,
        silence_threshold_dbfs: float,
        silence_seconds: int,
        track_change_silence_seconds: float = 1.25,
        minimum_playback_seconds: int = 30,
        input_type: Optional[str] = None,
        dynamic_rate_matching: bool = True,
    ) -> bool:
        cmd = {
            "type": "configure_input",
            "input": index,
            "device": device,
            "silence_threshold_dbfs": silence_threshold_dbfs,
            "silence_seconds": silence_seconds,
            "track_change_silence_seconds": track_change_silence_seconds,
            "minimum_playback_seconds": minimum_playback_seconds,
            # Always sent, as a JSON literal: the daemon replaces the input's
            # whole stored configuration on every call, so an omitted flag
            # would switch the option off.
            "dynamic_rate_matching": bool(dynamic_rate_matching),
        }
        # The daemon's reader has no notion of null; an unnamed type is an
        # absent key.
        if isinstance(input_type, str) and input_type.strip():
            cmd["input_type"] = input_type.strip().lower()
        with self._lock:
            resp = self._command(cmd)
            ok = bool(resp and resp.get("ok"))
            if not ok:
                logging.error(
                    "MonitorClient: configure_input(%d, %r) failed: %s",
                    index, device, (resp or {}).get("error", "no response"),
                )
            return ok

    def set_fifo(self, path: str) -> bool:
        with self._lock:
            resp = self._command({"type": "set_fifo", "path": path})
            ok = bool(resp and resp.get("ok"))
            if not ok:
                logging.error(
                    "MonitorClient: set_fifo(%r) failed: %s",
                    path, (resp or {}).get("error", "no response"),
                )
            return ok

    def start_input(self, index: int) -> bool:
        with self._lock:
            resp = self._command({"type": "start_input", "input": index})
            ok = bool(resp and resp.get("ok"))
            if not ok:
                logging.error(
                    "MonitorClient: start_input(%d) failed: %s",
                    index, (resp or {}).get("error", "no response"),
                )
            return ok

    def stop_input(self, index: int) -> bool:
        with self._lock:
            resp = self._command({"type": "stop_input", "input": index})
            return bool(resp and resp.get("ok"))

    def set_allow_capture(self, index: int, allow: bool) -> bool:
        with self._lock:
            resp = self._command({
                "type": "set_allow_capture",
                "input": index,
                "allow": allow,
            })
            return bool(resp and resp.get("ok"))

    def set_eq(self, index: int, bands: list[dict]) -> bool:
        with self._lock:
            resp = self._command({"type": "set_eq", "input": index, "bands": bands})
            return bool(resp and resp.get("ok"))

    def set_gain(self, index: int, gain_db: float) -> bool:
        with self._lock:
            resp = self._command({"type": "set_gain", "input": index, "gain_db": gain_db})
            return bool(resp and resp.get("ok"))

    def set_output_eq(self, bands: list[dict]) -> bool:
        with self._lock:
            resp = self._command({"type": "set_output_eq", "bands": bands})
            return bool(resp and resp.get("ok"))

    def set_output_gain(self, gain_db: float) -> bool:
        with self._lock:
            resp = self._command({"type": "set_output_gain", "gain_db": gain_db})
            return bool(resp and resp.get("ok"))

    def set_output_auto_trim(self, enabled: bool) -> bool:
        with self._lock:
            resp = self._command({"type": "set_output_auto_trim", "enabled": enabled})
            return bool(resp and resp.get("ok"))

    def set_repeat_enabled(
        self,
        enabled: bool,
        codec: str,
        target_minutes: Optional[int] = None,
    ) -> bool:
        """Push the global repeat-recording enable/codec/target-duration
        policy.

        target_minutes is the target-duration goal in minutes (10..600).
        None omits the field entirely -- the daemon's own sentinel
        (json_get_int(..., -1)) then leaves whatever it already has
        configured unchanged (defaults to 80 the first time the daemon
        starts). Tolerated to fail silently (returns False, no exception)
        against an old binary that does not recognise the command -- callers
        must not let this break startup/resync/reload.
        """
        with self._lock:
            cmd: dict = {
                "type": "set_repeat_enabled",
                "enabled": bool(enabled),
                "codec": str(codec),
            }
            if target_minutes is not None:
                cmd["target_minutes"] = int(target_minutes)
            resp = self._command(cmd)
            return bool(resp and resp.get("ok"))

    def set_repeat_armed_ack(self, armed: bool) -> Optional[dict]:
        """Arm/disarm session replay and return the parsed daemon ack (None
        when unreachable). See set_repeat_enabled re: old binaries."""
        with self._lock:
            return self._command({"type": "set_repeat_armed", "armed": bool(armed)})

    def set_repeat_armed(self, armed: bool) -> bool:
        """Arm/disarm session replay. See set_repeat_enabled re: old binaries."""
        resp = self.set_repeat_armed_ack(armed)
        return bool(resp and resp.get("ok"))

    def repeat_stop(self) -> Optional[dict]:
        """Stop repeat replay (fades out if currently replaying) and return
        the parsed daemon ack (None when unreachable)."""
        with self._lock:
            return self._command({"type": "repeat_stop"})

    def repeat_seek(self, position_seconds: float) -> Optional[dict]:
        """Seek repeat replay to position_seconds and return the parsed
        daemon ack (None when unreachable)."""
        with self._lock:
            return self._command({
                "type": "repeat_seek",
                "position_seconds": float(position_seconds),
            })

    def set_log_level(self, log_level: str) -> bool:
        with self._lock:
            normalized = normalize_log_level(log_level)
            resp = self._command({"type": "set_log_level", "level": normalized})
            ok = bool(resp and resp.get("ok"))
            if not ok:
                logging.error(
                    "MonitorClient: set_log_level(%r) failed: %s",
                    normalized, (resp or {}).get("error", "no response"),
                )
            return ok

    def start_output_dump(self, path: str, overwrite: bool = False) -> bool:
        """Begin recording output PCM to a WAV file at *path*.

        Returns True if the daemon accepted the request.  The C++ dispatcher
        rejects the call if a dump is already active; call stop_output_dump()
        first.
        """
        with self._lock:
            resp = self._command({
                "type": "start_output_dump",
                "path": path,
                "overwrite": overwrite,
            })
            ok = bool(resp and resp.get("ok"))
            if not ok:
                logging.error(
                    "MonitorClient: start_output_dump(%r) failed: %s",
                    path, (resp or {}).get("error", "no response"),
                )
            return ok

    def stop_output_dump(self) -> Optional[dict]:
        """Stop an active output dump and return the result dict.

        The result always has ok=True and includes was_active, frames_written,
        and frames_dropped.  Returns None only if the socket fails.
        """
        with self._lock:
            return self._command({"type": "stop_output_dump"})

    def get_status(self) -> Optional[dict]:
        """Return the parsed status dict, or None on failure."""
        with self._lock:
            return self._command({"type": "get_status"})

    def get_id_snapshot(
        self, index: int, max_seconds: int = 20
    ) -> "Optional[tuple[bytes, int]]":
        """Return (pcm_bytes, rate_hz) from the monitor's ID snapshot buffer.

        pcm_bytes is raw s16le mono PCM at rate_hz Hz.  Returns (b"", rate)
        when no frames are available yet.  Returns None on any protocol or
        socket failure.  The rate is read from the monitor ack so callers
        are not hardcoded to any particular sample rate.
        """
        with self._lock:
            resp = self._command({
                "type": "get_id_snapshot",
                "input": index,
                "max_seconds": max_seconds,
            })
            if not resp or not resp.get("ok"):
                return None
            frames = resp.get("frames", 0)
            rate = resp.get("rate")
            if not isinstance(frames, int) or isinstance(frames, bool):
                self.close()
                return None
            if frames < 0:
                self.close()
                return None
            if not isinstance(rate, int) or isinstance(rate, bool) or rate <= 0:
                self.close()
                return None
            if frames == 0:
                return (b"", rate)
            max_frames = max_seconds * rate
            if frames > max_frames:
                self.close()
                return None
            pcm = self._readbytes(frames * 2)
            if pcm is None:
                return None
            return (pcm, rate)



def get_monitor_socket_path() -> str:
    """Return the configured autostream_monitor socket path."""
    return (
        os.environ.get("AUTOSTREAM_MONITOR_SOCKET", "").strip()
        or MonitorClient.DEFAULT_SOCKET_PATH
    )


@contextlib.contextmanager
def _connected_monitor(socket_path: Optional[str] = None):
    """Context manager yielding a connected MonitorClient, or None if unavailable."""
    client = MonitorClient(socket_path or get_monitor_socket_path())
    try:
        yield client if client.connect() else None
    finally:
        client.close()
