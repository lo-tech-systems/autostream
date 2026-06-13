"""Priority 3 — MonitorClient socket protocol tests.

Tests cover _readline() fragmentation / EOF / error paths, _readbytes(),
_command() JSON send/receive, get_id_snapshot() binary payload, connect/close
idempotency, and individual command methods.

All tests inject a FakeSocket directly into MonitorClient._sock so no real
Unix domain sockets or daemon processes are needed.
"""
from __future__ import annotations

import json
import sys
import threading
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

REPO_ROOT = Path(__file__).parent.parent
_core = str(REPO_ROOT / "core")
if _core not in sys.path:
    sys.path.insert(0, _core)

import autostream_core as core
from autostream_core import MonitorClient


# ---------------------------------------------------------------------------
# FakeSocket
# ---------------------------------------------------------------------------

class FakeSocket:
    """Minimal socket stand-in.

    *chunks* are the byte strings returned from successive recv() calls.
    An empty list means EOF (recv returns b"").  Pass
    side_effect=OSError("…") to make the next recv() raise instead.
    """

    def __init__(self, *chunks: bytes, side_effect=None):
        self._chunks = list(chunks)
        self._side_effect = side_effect
        self.sent: list[bytes] = []
        self.closed = False

    def recv(self, _n: int) -> bytes:
        if self._side_effect is not None:
            raise self._side_effect
        if not self._chunks:
            return b""
        return self._chunks.pop(0)

    def sendall(self, data: bytes) -> None:
        self.sent.append(data)

    def close(self) -> None:
        self.closed = True

    def settimeout(self, _t) -> None:
        pass

    def connect(self, _addr) -> None:
        pass


def _client(sock: FakeSocket | None = None) -> MonitorClient:
    """Return a MonitorClient with an injected fake socket."""
    c = MonitorClient("/tmp/fake.sock")
    if sock is not None:
        c._sock = sock
    return c


# ---------------------------------------------------------------------------
# _readline
# ---------------------------------------------------------------------------

class TestReadline:
    def test_single_recv_returns_line(self):
        c = _client(FakeSocket(b"hello\n"))
        line = c._readline()
        assert line == b"hello"

    def test_assembles_across_fragments(self):
        c = _client(FakeSocket(b"hel", b"lo\n"))
        line = c._readline()
        assert line == b"hello"

    def test_uses_existing_recv_buf(self):
        c = _client(FakeSocket())
        c._recv_buf = b"preloaded\n"
        line = c._readline()
        assert line == b"preloaded"

    def test_leftover_stays_in_buf(self):
        c = _client(FakeSocket(b"first\nsecond"))
        line = c._readline()
        assert line == b"first"
        assert c._recv_buf == b"second"

    def test_eof_returns_none_and_disconnects(self):
        c = _client(FakeSocket())   # empty → EOF on first recv
        line = c._readline()
        assert line is None
        assert not c.is_connected()

    def test_socket_error_returns_none_and_disconnects(self):
        c = _client(FakeSocket(side_effect=OSError("reset")))
        line = c._readline()
        assert line is None
        assert not c.is_connected()

    def test_multi_line_buf_returns_first(self):
        c = _client(FakeSocket())
        c._recv_buf = b"line1\nline2\n"
        assert c._readline() == b"line1"
        assert c._recv_buf == b"line2\n"


# ---------------------------------------------------------------------------
# _readbytes
# ---------------------------------------------------------------------------

class TestReadbytes:
    def test_single_recv_exact(self):
        c = _client(FakeSocket(b"abcde"))
        data = c._readbytes(5)
        assert data == b"abcde"

    def test_assembles_across_fragments(self):
        c = _client(FakeSocket(b"ab", b"cde"))
        data = c._readbytes(5)
        assert data == b"abcde"

    def test_uses_pre_buffered_bytes(self):
        c = _client(FakeSocket())
        c._recv_buf = b"hello"
        data = c._readbytes(3)
        assert data == b"hel"
        assert c._recv_buf == b"lo"

    def test_eof_returns_none_and_disconnects(self):
        c = _client(FakeSocket())   # EOF immediately
        data = c._readbytes(5)
        assert data is None
        assert not c.is_connected()

    def test_socket_error_returns_none_and_disconnects(self):
        c = _client(FakeSocket(side_effect=OSError("broken pipe")))
        data = c._readbytes(5)
        assert data is None
        assert not c.is_connected()

    def test_zero_bytes_returns_empty(self):
        c = _client(FakeSocket())
        c._recv_buf = b"leftover"
        data = c._readbytes(0)
        assert data == b""


# ---------------------------------------------------------------------------
# _command
# ---------------------------------------------------------------------------

class TestCommand:
    def test_sends_json_with_newline(self):
        sock = FakeSocket(b'{"ok": true}\n')
        c = _client(sock)
        c._command({"type": "foo"})
        assert sock.sent
        sent = b"".join(sock.sent)
        decoded = json.loads(sent.strip())
        assert decoded == {"type": "foo"}
        assert sent.endswith(b"\n")

    def test_parses_response_dict(self):
        c = _client(FakeSocket(b'{"ok": true, "data": 42}\n'))
        resp = c._command({"type": "get_status"})
        assert resp == {"ok": True, "data": 42}

    def test_returns_none_when_socket_is_none(self):
        c = MonitorClient("/tmp/fake.sock")
        assert c._sock is None
        assert c._command({"type": "foo"}) is None

    def test_invalid_json_response_returns_none_and_disconnects(self):
        c = _client(FakeSocket(b"not-json\n"))
        resp = c._command({"type": "foo"})
        assert resp is None
        assert not c.is_connected()

    def test_eof_response_returns_none(self):
        c = _client(FakeSocket())
        resp = c._command({"type": "foo"})
        assert resp is None
        assert not c.is_connected()


# ---------------------------------------------------------------------------
# connect / close idempotency
# ---------------------------------------------------------------------------

class TestConnectClose:
    def test_close_when_disconnected_is_safe(self):
        c = MonitorClient("/tmp/fake.sock")
        c.close()   # must not raise
        c.close()   # second call also safe
        assert not c.is_connected()

    def test_is_connected_reflects_sock_state(self):
        c = MonitorClient("/tmp/fake.sock")
        assert not c.is_connected()
        c._sock = FakeSocket()
        assert c.is_connected()
        c.close()
        assert not c.is_connected()

    def test_close_closes_underlying_socket(self):
        sock = FakeSocket()
        c = _client(sock)
        c.close()
        assert sock.closed

    def test_close_clears_recv_buf(self):
        c = _client(FakeSocket())
        c._recv_buf = b"leftover"
        c.close()
        assert c._recv_buf == b""

    def test_connect_calls_close_on_existing_socket(self):
        old_sock = FakeSocket()
        c = _client(old_sock)
        # connect() to a non-existent path will fail, but close() should be called.
        # Patch autostream_core.socket so AF_UNIX exists even on Windows.
        import socket as _socket_mod
        fake_socket_mod = MagicMock(wraps=_socket_mod)
        fake_socket_mod.AF_UNIX = getattr(_socket_mod, "AF_UNIX", 1)
        fake_socket_mod.SOCK_STREAM = _socket_mod.SOCK_STREAM
        fake_new_sock = MagicMock()
        fake_new_sock.connect.side_effect = OSError("no such file")
        fake_socket_mod.socket.return_value = fake_new_sock
        with patch("autostream_core.socket", fake_socket_mod):
            c.connect()
        assert old_sock.closed

    def test_connect_returns_false_on_os_error(self):
        c = MonitorClient("/nonexistent/path.sock")
        import socket as _socket_mod
        fake_socket_mod = MagicMock(wraps=_socket_mod)
        fake_socket_mod.AF_UNIX = getattr(_socket_mod, "AF_UNIX", 1)
        fake_socket_mod.SOCK_STREAM = _socket_mod.SOCK_STREAM
        fake_new_sock = MagicMock()
        fake_new_sock.connect.side_effect = OSError("no such file")
        fake_socket_mod.socket.return_value = fake_new_sock
        with patch("autostream_core.socket", fake_socket_mod):
            result = c.connect()
        assert result is False
        assert not c.is_connected()


# ---------------------------------------------------------------------------
# list_devices
# ---------------------------------------------------------------------------

class TestListDevices:
    def test_success_returns_devices_list(self):
        payload = {"ok": True, "devices": [{"hw": "hw:0,0", "name": "USB Audio"}]}
        c = _client(FakeSocket((json.dumps(payload) + "\n").encode()))
        devices = c.list_devices()
        assert devices == [{"hw": "hw:0,0", "name": "USB Audio"}]

    def test_ok_false_returns_none(self):
        payload = {"ok": False, "error": "unavailable"}
        c = _client(FakeSocket((json.dumps(payload) + "\n").encode()))
        devices = c.list_devices()
        assert devices is None

    def test_no_response_returns_none(self):
        c = _client(FakeSocket())   # EOF
        devices = c.list_devices()
        assert devices is None

    def test_command_type_is_list_devices(self):
        payload = {"ok": True, "devices": []}
        sock = FakeSocket((json.dumps(payload) + "\n").encode())
        c = _client(sock)
        c.list_devices()
        sent = b"".join(sock.sent)
        cmd = json.loads(sent.strip())
        assert cmd["type"] == "list_devices"


# ---------------------------------------------------------------------------
# configure_input
# ---------------------------------------------------------------------------

class TestConfigureInput:
    def test_sends_all_required_fields(self):
        payload = {"ok": True}
        sock = FakeSocket((json.dumps(payload) + "\n").encode())
        c = _client(sock)
        ok = c.configure_input(
            index=0,
            device="hw:1,0",
            silence_threshold_dbfs=-50.0,
            silence_seconds=5,
        )
        assert ok is True
        sent = b"".join(sock.sent)
        cmd = json.loads(sent.strip())
        assert cmd["type"] == "configure_input"
        assert cmd["input"] == 0
        assert cmd["device"] == "hw:1,0"
        assert cmd["silence_threshold_dbfs"] == -50.0
        assert cmd["silence_seconds"] == 5

    def test_returns_false_on_ok_false(self):
        payload = {"ok": False, "error": "bad device"}
        c = _client(FakeSocket((json.dumps(payload) + "\n").encode()))
        ok = c.configure_input(1, "hw:bad", -40.0, 10)
        assert ok is False


# ---------------------------------------------------------------------------
# set_log_level
# ---------------------------------------------------------------------------

class TestSetLogLevel:
    def test_normalizes_level_before_sending(self):
        payload = {"ok": True}
        sock = FakeSocket((json.dumps(payload) + "\n").encode())
        c = _client(sock)
        c.set_log_level("DEBUG")
        sent = b"".join(sock.sent)
        cmd = json.loads(sent.strip())
        assert cmd["type"] == "set_log_level"
        assert cmd["level"] == "debug"

    def test_returns_false_on_failure(self):
        payload = {"ok": False}
        c = _client(FakeSocket((json.dumps(payload) + "\n").encode()))
        ok = c.set_log_level("info")
        assert ok is False


# ---------------------------------------------------------------------------
# get_id_snapshot
# ---------------------------------------------------------------------------

class TestGetIdSnapshot:
    def test_returns_pcm_bytes(self):
        frames = 10
        pcm = b"\x00\x01" * frames  # frames * 2 bytes
        ack = json.dumps({"ok": True, "frames": frames}) + "\n"
        sock = FakeSocket(ack.encode(), pcm)
        c = _client(sock)
        result = c.get_id_snapshot(0, max_seconds=5)
        assert result == pcm

    def test_zero_frames_returns_empty_bytes(self):
        ack = json.dumps({"ok": True, "frames": 0}) + "\n"
        c = _client(FakeSocket(ack.encode()))
        result = c.get_id_snapshot(0)
        assert result == b""

    def test_ok_false_returns_none(self):
        ack = json.dumps({"ok": False, "error": "no data"}) + "\n"
        c = _client(FakeSocket(ack.encode()))
        result = c.get_id_snapshot(0)
        assert result is None

    def test_no_response_returns_none(self):
        c = _client(FakeSocket())
        result = c.get_id_snapshot(0)
        assert result is None

    def test_sends_correct_command_fields(self):
        ack = json.dumps({"ok": True, "frames": 0}) + "\n"
        sock = FakeSocket(ack.encode())
        c = _client(sock)
        c.get_id_snapshot(index=2, max_seconds=15)
        sent = b"".join(sock.sent)
        cmd = json.loads(sent.strip())
        assert cmd["type"] == "get_id_snapshot"
        assert cmd["input"] == 2
        assert cmd["max_seconds"] == 15


# ---------------------------------------------------------------------------
# Thread safety: lock prevents interleaving
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# _command: malformed and edge-case responses
# ---------------------------------------------------------------------------

class TestCommandEdgeCases:
    def test_invalid_utf8_returns_none_and_disconnects(self):
        # json.loads(b"\xff\xfe") raises JSONDecodeError/ValueError; _command catches it.
        c = _client(FakeSocket(b"\xff\xfe\n"))
        resp = c._command({"type": "get_status"})
        assert resp is None
        assert not c.is_connected()

    def test_non_object_list_response_returns_none_and_disconnects(self):
        c = _client(FakeSocket(b'["not", "an", "object"]\n'))
        resp = c._command({"type": "foo"})
        assert resp is None
        assert not c.is_connected()

    def test_non_object_string_response_returns_none_and_disconnects(self):
        c = _client(FakeSocket(b'"just a string"\n'))
        resp = c._command({"type": "foo"})
        assert resp is None
        assert not c.is_connected()

    def test_non_object_number_response_returns_none_and_disconnects(self):
        c = _client(FakeSocket(b"42\n"))
        resp = c._command({"type": "foo"})
        assert resp is None
        assert not c.is_connected()

    def test_null_response_returns_none_and_disconnects(self):
        c = _client(FakeSocket(b"null\n"))
        resp = c._command({"type": "foo"})
        assert resp is None
        assert not c.is_connected()


# ---------------------------------------------------------------------------
# get_id_snapshot: length validation
# ---------------------------------------------------------------------------

class TestGetIdSnapshotLengths:
    def test_negative_frames_returns_empty(self):
        # frames <= 0 should return b"" (the production guard uses frames <= 0)
        ack = json.dumps({"ok": True, "frames": -1}) + "\n"
        c = _client(FakeSocket(ack.encode()))
        result = c.get_id_snapshot(0)
        assert result == b""

    def test_excessive_frames_truncated_to_available_bytes(self):
        # If the daemon claims more frames than it actually sends, _readbytes returns
        # None on EOF. The caller gets None back.
        ack = json.dumps({"ok": True, "frames": 10000}) + "\n"
        # Only supply 4 bytes instead of 20000 (frames * 2)
        c = _client(FakeSocket(ack.encode(), b"\x00\x01\x00\x01"))
        result = c.get_id_snapshot(0)
        assert result is None
        assert not c.is_connected()

    def test_truncated_payload_returns_none_and_disconnects(self):
        frames = 100
        ack = json.dumps({"ok": True, "frames": frames}) + "\n"
        # Only half the expected bytes provided
        partial_pcm = b"\x00\x01" * (frames // 2)
        c = _client(FakeSocket(ack.encode(), partial_pcm))
        result = c.get_id_snapshot(0)
        assert result is None
        assert not c.is_connected()


# ---------------------------------------------------------------------------
# Public command methods: send correct type + field contract
# ---------------------------------------------------------------------------

class TestPublicCommands:
    def _ok(self):
        return (json.dumps({"ok": True}) + "\n").encode()

    def _fail(self):
        return (json.dumps({"ok": False, "error": "nope"}) + "\n").encode()

    def test_set_fifo_sends_path(self):
        sock = FakeSocket(self._ok())
        c = _client(sock)
        ok = c.set_fifo("/tmp/audio.fifo")
        assert ok is True
        cmd = json.loads(b"".join(sock.sent).strip())
        assert cmd["type"] == "set_fifo"
        assert cmd["path"] == "/tmp/audio.fifo"

    def test_set_fifo_returns_false_on_failure(self):
        c = _client(FakeSocket(self._fail()))
        assert c.set_fifo("/tmp/bad.fifo") is False

    def test_start_input_sends_index(self):
        sock = FakeSocket(self._ok())
        c = _client(sock)
        ok = c.start_input(1)
        assert ok is True
        cmd = json.loads(b"".join(sock.sent).strip())
        assert cmd["type"] == "start_input"
        assert cmd["input"] == 1

    def test_stop_input_sends_index(self):
        sock = FakeSocket(self._ok())
        c = _client(sock)
        ok = c.stop_input(2)
        assert ok is True
        cmd = json.loads(b"".join(sock.sent).strip())
        assert cmd["type"] == "stop_input"
        assert cmd["input"] == 2

    def test_set_allow_capture_sends_bool(self):
        sock = FakeSocket(self._ok())
        c = _client(sock)
        ok = c.set_allow_capture(1, True)
        assert ok is True
        cmd = json.loads(b"".join(sock.sent).strip())
        assert cmd["type"] == "set_allow_capture"
        assert cmd["allow"] is True

    def test_set_eq_sends_bands(self):
        bands = [{"type": "Peak", "freq_hz": 1000.0, "gain_db": 3.0, "q": 0.707}]
        sock = FakeSocket(self._ok())
        c = _client(sock)
        ok = c.set_eq(1, bands)
        assert ok is True
        cmd = json.loads(b"".join(sock.sent).strip())
        assert cmd["type"] == "set_eq"
        assert cmd["input"] == 1
        assert cmd["bands"] == bands

    def test_set_gain_sends_gain_db(self):
        sock = FakeSocket(self._ok())
        c = _client(sock)
        ok = c.set_gain(2, -3.5)
        assert ok is True
        cmd = json.loads(b"".join(sock.sent).strip())
        assert cmd["type"] == "set_gain"
        assert cmd["input"] == 2
        assert cmd["gain_db"] == pytest.approx(-3.5)

    def test_set_output_eq_sends_bands(self):
        bands = [{"type": "LowShelf", "freq_hz": 200.0, "gain_db": 1.0, "q": 0.7}]
        sock = FakeSocket(self._ok())
        c = _client(sock)
        ok = c.set_output_eq(bands)
        assert ok is True
        cmd = json.loads(b"".join(sock.sent).strip())
        assert cmd["type"] == "set_output_eq"
        assert cmd["bands"] == bands

    def test_set_output_gain_sends_gain_db(self):
        sock = FakeSocket(self._ok())
        c = _client(sock)
        ok = c.set_output_gain(2.0)
        assert ok is True
        cmd = json.loads(b"".join(sock.sent).strip())
        assert cmd["type"] == "set_output_gain"
        assert cmd["gain_db"] == pytest.approx(2.0)

    def test_set_output_auto_trim_sends_bool(self):
        sock = FakeSocket(self._ok())
        c = _client(sock)
        ok = c.set_output_auto_trim(True)
        assert ok is True
        cmd = json.loads(b"".join(sock.sent).strip())
        assert cmd["type"] == "set_output_auto_trim"
        assert cmd["enabled"] is True

    def test_get_status_returns_dict(self):
        payload = {"ok": True, "inputs": []}
        c = _client(FakeSocket((json.dumps(payload) + "\n").encode()))
        result = c.get_status()
        assert result == payload

    def test_get_status_returns_none_on_failure(self):
        c = _client(FakeSocket(self._fail()))
        result = c.get_status()
        # get_status returns the raw response dict (ok or not); check it's a dict or None
        assert result is not None  # ok=False response is still returned as dict
        assert result["ok"] is False

    def test_start_input_returns_false_on_failure(self):
        c = _client(FakeSocket(self._fail()))
        assert c.start_input(1) is False


# ---------------------------------------------------------------------------
# Thread safety: lock prevents interleaving
# ---------------------------------------------------------------------------

class TestThreadSafety:
    def test_concurrent_list_devices_return_own_results(self):
        """Two threads calling list_devices on separate clients don't interfere."""
        results = []
        errors = []

        def worker(n):
            payload = {"ok": True, "devices": [{"hw": f"hw:{n},0"}]}
            sock = FakeSocket((json.dumps(payload) + "\n").encode())
            c = _client(sock)
            try:
                devices = c.list_devices()
                results.append(devices)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=5)

        assert not errors
        assert len(results) == 4
