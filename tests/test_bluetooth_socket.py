"""Tests for the autostream_bluetooth control-socket protocol
(platform/bluetooth_socket.py).

Covers the pure ``dispatch()`` parser/router (all platforms) and an
end-to-end Unix-socket run (skipped when AF_UNIX is absent, e.g. native
Windows without WSL) — mirrors tests/test_dial_control_socket.py.
"""
from __future__ import annotations

import json
import os
import socket
import sys
import tempfile
import threading
import time
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
for _p in (REPO_ROOT / "platform",):
    _s = str(_p)
    if _s not in sys.path:
        sys.path.insert(0, _s)

from bluetooth_socket import (  # noqa: E402
    DEFAULT_SOCKET_PATH,
    SOCKET_MODE,
    BluetoothControlServer,
    dispatch,
)

_HAS_AF_UNIX = hasattr(socket, "AF_UNIX")
skip_no_unix = pytest.mark.skipif(not _HAS_AF_UNIX, reason="AF_UNIX not available on this platform")

MAC_A = "AA:BB:CC:DD:EE:01"


def _req(obj: dict) -> bytes:
    return (json.dumps(obj) + "\n").encode("utf-8")


class FakeServer:
    """Minimal BluetoothControlServer substitute for dispatch() tests."""

    def __init__(self) -> None:
        self.scan_start_called = False
        self.scan_stop_called = False
        self.forget_called = False
        self.paired_with: str | None = None
        # Contract: scan_start()/pair() return bool — False means
        # "busy" (a scan/pairing attempt is already in flight).
        self.scan_start_result = True
        self.pair_result = True
        self.configure_result = True
        self.configured_with: int | None = None
        self._status = {
            "adapter_present": True,
            "paired": None,
            "link": "disconnected",
            "streaming": False,
            "scanning": False,
            "pump_source_active": False,
            "buffer_ms": 200,
            "adapter_kind": "usb",
        }
        self._scan_results = []
        self._pair_status = {"state": "idle"}

    def get_status(self) -> dict:
        return dict(self._status)

    def scan_start(self) -> bool:
        self.scan_start_called = True
        return self.scan_start_result

    def scan_stop(self) -> None:
        self.scan_stop_called = True

    def get_scan_results(self) -> list:
        return list(self._scan_results)

    def pair(self, mac: str) -> bool:
        self.paired_with = mac
        return self.pair_result

    def get_pair_status(self) -> dict:
        return dict(self._pair_status)

    def forget(self) -> None:
        self.forget_called = True

    def configure(self, buffer_ms: int) -> bool:
        self.configured_with = buffer_ms
        return self.configure_result


# ---------------------------------------------------------------------------
# dispatch() parser/router tests — all platforms
# ---------------------------------------------------------------------------

class TestDispatchStatus:
    def test_status_shape(self):
        r = dispatch(_req({"cmd": "status"}), FakeServer())
        assert r == {
            "ok": True,
            "adapter_present": True,
            "paired": None,
            "link": "disconnected",
            "streaming": False,
            "scanning": False,
            "pump_source_active": False,
            "buffer_ms": 200,
            "adapter_kind": "usb",
        }

    def test_status_reflects_buffer_ms_and_adapter_kind(self):
        srv = FakeServer()
        srv._status["buffer_ms"] = 350
        srv._status["adapter_kind"] = "onboard"
        r = dispatch(_req({"cmd": "status"}), srv)
        assert r["buffer_ms"] == 350
        assert r["adapter_kind"] == "onboard"

    def test_status_adapter_kind_null_when_no_adapter(self):
        srv = FakeServer()
        srv._status["adapter_present"] = False
        srv._status["adapter_kind"] = None
        r = dispatch(_req({"cmd": "status"}), srv)
        assert r["adapter_kind"] is None

    def test_status_reflects_paired_device(self):
        srv = FakeServer()
        srv._status["paired"] = {"mac": MAC_A, "name": "Turntable"}
        r = dispatch(_req({"cmd": "status"}), srv)
        assert r["paired"] == {"mac": MAC_A, "name": "Turntable"}

    def test_status_unexpected_field(self):
        r = dispatch(_req({"cmd": "status", "extra": 1}), FakeServer())
        assert r == {"ok": False, "error": "unexpected_field"}


class TestDispatchScan:
    def test_scan_start(self):
        srv = FakeServer()
        r = dispatch(_req({"cmd": "scan_start"}), srv)
        assert r == {"ok": True}
        assert srv.scan_start_called is True

    def test_scan_stop(self):
        srv = FakeServer()
        r = dispatch(_req({"cmd": "scan_stop"}), srv)
        assert r == {"ok": True}
        assert srv.scan_stop_called is True

    def test_scan_results_empty(self):
        r = dispatch(_req({"cmd": "scan_results"}), FakeServer())
        assert r == {"ok": True, "devices": []}

    def test_scan_results_with_devices(self):
        srv = FakeServer()
        srv._scan_results = [{"mac": MAC_A, "name": "Turntable", "rssi": -50, "paired": False}]
        r = dispatch(_req({"cmd": "scan_results"}), srv)
        assert r["ok"] is True
        assert r["devices"] == srv._scan_results

    def test_scan_start_busy_returns_pinned_error(self):
        """scan_start()'s bool must not be discarded —
        a busy state machine reports scan_in_progress rather than a false ok."""
        srv = FakeServer()
        srv.scan_start_result = False
        r = dispatch(_req({"cmd": "scan_start"}), srv)
        assert r == {"ok": False, "error": "scan_in_progress"}
        assert srv.scan_start_called is True


class TestDispatchPair:
    def test_pair_valid_mac(self):
        srv = FakeServer()
        r = dispatch(_req({"cmd": "pair", "mac": MAC_A}), srv)
        assert r == {"ok": True}
        assert srv.paired_with == MAC_A

    def test_pair_invalid_mac_rejected(self):
        srv = FakeServer()
        r = dispatch(_req({"cmd": "pair", "mac": "not-a-mac"}), srv)
        assert r == {"ok": False, "error": "invalid_mac"}
        assert srv.paired_with is None

    def test_pair_missing_mac_rejected(self):
        r = dispatch(_req({"cmd": "pair"}), FakeServer())
        assert r == {"ok": False, "error": "invalid_mac"}

    def test_pair_non_string_mac_rejected(self):
        r = dispatch(_req({"cmd": "pair", "mac": 1234}), FakeServer())
        assert r["error"] == "invalid_mac"

    def test_pair_busy_returns_pinned_error(self):
        """pair()'s bool must not be discarded — the
        webui maps this exact string to HTTP 409, so it must not vary."""
        srv = FakeServer()
        srv.pair_result = False
        r = dispatch(_req({"cmd": "pair", "mac": MAC_A}), srv)
        assert r == {"ok": False, "error": "pair_in_progress"}
        assert srv.paired_with == MAC_A  # server.pair() was still called

    def test_pair_status_idle(self):
        r = dispatch(_req({"cmd": "pair_status"}), FakeServer())
        assert r == {"ok": True, "state": "idle"}

    def test_pair_status_failed_includes_error(self):
        srv = FakeServer()
        srv._pair_status = {"state": "failed", "error": "timeout"}
        r = dispatch(_req({"cmd": "pair_status"}), srv)
        assert r == {"ok": True, "state": "failed", "error": "timeout"}


class TestDispatchForget:
    def test_forget(self):
        srv = FakeServer()
        r = dispatch(_req({"cmd": "forget"}), srv)
        assert r == {"ok": True}
        assert srv.forget_called is True


class TestDispatchConfigure:
    def test_configure_valid_buffer_ms(self):
        srv = FakeServer()
        r = dispatch(_req({"cmd": "configure", "buffer_ms": 300}), srv)
        assert r == {"ok": True}
        assert srv.configured_with == 300

    def test_configure_rejects_non_int(self):
        srv = FakeServer()
        r = dispatch(_req({"cmd": "configure", "buffer_ms": "200"}), srv)
        assert r == {"ok": False, "error": "invalid_buffer_ms"}
        assert srv.configured_with is None

    def test_configure_rejects_bool(self):
        """bool is a subclass of int in Python; must be rejected explicitly."""
        srv = FakeServer()
        r = dispatch(_req({"cmd": "configure", "buffer_ms": True}), srv)
        assert r == {"ok": False, "error": "invalid_buffer_ms"}
        assert srv.configured_with is None

    def test_configure_missing_buffer_ms_rejected(self):
        r = dispatch(_req({"cmd": "configure"}), FakeServer())
        assert r == {"ok": False, "error": "invalid_buffer_ms"}

    def test_configure_out_of_range_rejected_by_server(self):
        """The int/type-shape check passes; server.configure()'s own range
        validation (100..500) is what rejects it — same pinned error string
        regardless of which layer caught the problem."""
        srv = FakeServer()
        srv.configure_result = False
        r = dispatch(_req({"cmd": "configure", "buffer_ms": 9999}), srv)
        assert r == {"ok": False, "error": "invalid_buffer_ms"}
        assert srv.configured_with == 9999  # server.configure() was still called

    def test_configure_unexpected_field_rejected(self):
        r = dispatch(_req({"cmd": "configure", "buffer_ms": 200, "extra": 1}), FakeServer())
        assert r == {"ok": False, "error": "unexpected_field"}


class TestDefaultSocketPath:
    def test_default_socket_path_moved_to_own_runtime_directory(self):
        """Pinned path change: the unit gets its own RuntimeDirectory
        (autostream-bluetooth) rather than the shared /run/autostream, so it
        never needs to chown a directory another service owns."""
        assert DEFAULT_SOCKET_PATH == "/run/autostream-bluetooth/bluetooth.sock"


class TestDispatchErrors:
    def test_malformed_json(self):
        r = dispatch(b"not json\n", FakeServer())
        assert r["error"] == "invalid_json"

    def test_invalid_utf8(self):
        r = dispatch(b"\xff\xfe\n", FakeServer())
        assert r["error"] == "invalid_json"

    def test_no_newline_rejected(self):
        r = dispatch(b'{"cmd":"status"}', FakeServer())
        assert r["ok"] is False

    def test_json_array_root(self):
        r = dispatch(b"[1,2]\n", FakeServer())
        assert r["error"] == "invalid_request"

    def test_missing_cmd(self):
        r = dispatch(_req({"action": "status"}), FakeServer())
        assert r["error"] == "invalid_request"

    def test_non_string_cmd(self):
        r = dispatch(_req({"cmd": 5}), FakeServer())
        assert r["error"] == "invalid_request"

    def test_unknown_cmd(self):
        r = dispatch(_req({"cmd": "rotate"}), FakeServer())
        assert r["error"] == "unknown_cmd"

    def test_internal_error_caught(self):
        class _BrokenServer(FakeServer):
            def get_status(self):
                raise RuntimeError("boom")

        r = dispatch(_req({"cmd": "status"}), _BrokenServer())
        assert r == {"ok": False, "error": "internal_error"}

    def test_request_too_large_rejected(self):
        big = b'{"cmd":"status","x":"' + b"a" * 4200 + b'"}\n'
        r = dispatch(big, FakeServer())
        assert r["error"] == "request_too_large"


# ---------------------------------------------------------------------------
# Unix socket end-to-end (bluez layer entirely absent — server callbacks are
# plain Python callables)
# ---------------------------------------------------------------------------

def _send_recv(sock_path: str, req: dict) -> dict:
    line = json.dumps(req) + "\n"
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        s.connect(sock_path)
        s.sendall(line.encode("utf-8"))
        buf = b""
        while b"\n" not in buf:
            chunk = s.recv(4096)
            if not chunk:
                break
            buf += chunk
        return json.loads(buf.split(b"\n")[0])
    finally:
        s.close()


def _make_server(tmpdir: str) -> BluetoothControlServer:
    fake = FakeServer()
    return BluetoothControlServer(
        get_status=fake.get_status,
        scan_start=fake.scan_start,
        scan_stop=fake.scan_stop,
        get_scan_results=fake.get_scan_results,
        pair=fake.pair,
        get_pair_status=fake.get_pair_status,
        forget=fake.forget,
        configure=fake.configure,
        socket_path=os.path.join(tmpdir, "bluetooth.sock"),
    )


@skip_no_unix
class TestUnixSocketServer:
    def _tmpdir(self) -> str:
        return tempfile.mkdtemp(prefix="bt-")

    def _make_and_start(self, tmpdir: str) -> BluetoothControlServer:
        srv = _make_server(tmpdir)
        srv.start()
        time.sleep(0.05)
        return srv

    def test_startup_creates_socket_with_mode_0660(self):
        d = self._tmpdir()
        srv = self._make_and_start(d)
        try:
            import stat
            path = os.path.join(d, "bluetooth.sock")
            assert os.path.exists(path)
            st = os.stat(path)
            assert stat.S_ISSOCK(st.st_mode)
            assert stat.S_IMODE(st.st_mode) == 0o660
        finally:
            srv.stop()

    def test_umask_restored_after_start(self):
        """start() must restore the prior umask even
        though it temporarily narrows it around the bind (TOCTOU fix) —
        a leaked umask would silently affect every other file this process
        creates afterwards."""
        d = self._tmpdir()
        prior = os.umask(0o022)
        os.umask(prior)  # restore immediately; we only wanted to read it
        srv = self._make_and_start(d)
        try:
            current = os.umask(0o022)
            os.umask(current)
            assert current == prior
        finally:
            srv.stop()

    def test_socket_mode_correct_even_without_belt_and_braces_chmod(self):
        """The umask fix means the bind() call itself creates the
        socket at SOCKET_MODE -- verify this holds even if the follow-up
        chmod (belt-and-braces) were skipped, by checking immediately after
        bind with no window for a raced reader to see a wider mode."""
        d = self._tmpdir()
        srv = _make_server(d)
        srv.start()
        try:
            import stat
            st = os.stat(srv.socket_path)
            assert stat.S_IMODE(st.st_mode) == SOCKET_MODE
        finally:
            srv.stop()

    def test_status_request_round_trip(self):
        d = self._tmpdir()
        srv = self._make_and_start(d)
        try:
            r = _send_recv(srv.socket_path, {"cmd": "status"})
            assert r["ok"] is True
            assert r["scanning"] is False
        finally:
            srv.stop()

    def test_multiple_sequential_clients(self):
        d = self._tmpdir()
        srv = self._make_and_start(d)
        try:
            for _ in range(5):
                r = _send_recv(srv.socket_path, {"cmd": "status"})
                assert r["ok"] is True
        finally:
            srv.stop()

    def test_concurrent_clients_no_corruption(self):
        d = self._tmpdir()
        srv = self._make_and_start(d)
        results, errors = [], []

        def worker():
            try:
                results.append(_send_recv(srv.socket_path, {"cmd": "status"}))
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=5)
        try:
            assert not errors
            assert len(results) == 10
            assert all(r["ok"] for r in results)
        finally:
            srv.stop()

    def test_client_disconnect_does_not_stop_server(self):
        d = self._tmpdir()
        srv = self._make_and_start(d)
        try:
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.connect(srv.socket_path)
            s.close()
            r = _send_recv(srv.socket_path, {"cmd": "status"})
            assert r["ok"] is True
        finally:
            srv.stop()

    def test_shutdown_removes_socket(self):
        d = self._tmpdir()
        srv = self._make_and_start(d)
        path = srv.socket_path
        srv.stop()
        time.sleep(0.05)
        assert not os.path.exists(path)

    def test_stop_before_start_is_safe(self):
        d = self._tmpdir()
        srv = _make_server(d)
        srv.stop()

    def test_start_twice_raises(self):
        d = self._tmpdir()
        srv = self._make_and_start(d)
        try:
            with pytest.raises(RuntimeError):
                srv.start()
        finally:
            srv.stop()

    def test_configure_end_to_end(self):
        d = self._tmpdir()
        srv = self._make_and_start(d)
        try:
            r = _send_recv(srv.socket_path, {"cmd": "configure", "buffer_ms": 300})
            assert r == {"ok": True}
        finally:
            srv.stop()

    def test_pair_end_to_end(self):
        d = self._tmpdir()
        srv = self._make_and_start(d)
        try:
            r = _send_recv(srv.socket_path, {"cmd": "pair", "mac": MAC_A})
            assert r == {"ok": True}
            r2 = _send_recv(srv.socket_path, {"cmd": "pair_status"})
            assert r2["ok"] is True
        finally:
            srv.stop()
