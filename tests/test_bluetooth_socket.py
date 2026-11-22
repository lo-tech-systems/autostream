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

from bluetooth_loop import LoopCallTimeout  # noqa: E402
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


class FakeBridge:
    """Pass-through stand-in for LoopBridge: runs fn(*args) inline on the
    calling thread instead of marshaling onto a real loop -- exercises every
    dispatch()/handler code path without needing GLib or a second thread."""

    def call_sync(self, fn, *args, timeout=None):
        return fn(*args)


class TimingOutBridge:
    """Simulates a wedged loop: every call_sync() times out instead of
    running fn."""

    def call_sync(self, fn, *args, timeout=None):
        raise LoopCallTimeout("simulated wedged loop")


class FakeServer:
    """Minimal BluetoothControlServer substitute for dispatch() tests."""

    def __init__(self, bridge=None) -> None:
        self.bridge = bridge if bridge is not None else FakeBridge()
        self.window_calls: list = []
        self.forget_called = False
        self.paired_with: str | None = None
        # Contract: window_start()/window_stop()/pair() return None on
        # success, else the window machine's reply code.
        self.window_start_result = None
        self.window_stop_result = None
        self.pair_result = None
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
            "version": "0.5.2",
            "window_state": "idle",
            "held": None,
        }
        self._poll = {"state": "idle", "remaining_s": None, "devices": [], "adopting": None,
                      "last_close": None, "last_error": None}

    def get_status(self) -> dict:
        return dict(self._status)

    def window_start(self):
        self.window_calls.append("start")
        return self.window_start_result

    def window_stop(self):
        self.window_calls.append("stop")
        return self.window_stop_result

    def window_poll(self) -> dict:
        self.window_calls.append("poll")
        return dict(self._poll)

    def pair(self, mac: str):
        self.paired_with = mac
        return self.pair_result

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
            "loopback_held": False,
            "loopback_locked_out": False,
            "buffer_ms": 200,
            "adapter_kind": "usb",
            "adapter_blocked": False,
            "version": "0.5.2",
            "window_state": "idle",
            "held": None,
        }

    def test_status_window_state_and_held_passthrough(self):
        srv = FakeServer()
        srv._status["window_state"] = "open"
        srv._status["held"] = {"mac": MAC_A}
        r = dispatch(_req({"cmd": "status"}), srv)
        assert r["window_state"] == "open"
        assert r["held"] == {"mac": MAC_A}

    def test_status_loopback_held_passthrough(self):
        srv = FakeServer()
        srv._status["loopback_held"] = True
        r = dispatch(_req({"cmd": "status"}), srv)
        assert r["loopback_held"] is True

    def test_status_loopback_locked_out_passthrough(self):
        srv = FakeServer()
        srv._status["loopback_locked_out"] = True
        r = dispatch(_req({"cmd": "status"}), srv)
        assert r["loopback_locked_out"] is True

    def test_status_codec_and_rate_forwarded_when_present(self):
        # The daemon includes codec/sample_rate only while an A2DP transport
        # is active; the envelope must forward them on the same terms.
        srv = FakeServer()
        srv._status["codec"] = "SBC"
        srv._status["sample_rate"] = 44100
        r = dispatch(_req({"cmd": "status"}), srv)
        assert r["codec"] == "SBC"
        assert r["sample_rate"] == 44100

    def test_status_codec_and_rate_absent_when_idle(self):
        r = dispatch(_req({"cmd": "status"}), FakeServer())
        assert "codec" not in r
        assert "sample_rate" not in r

    def test_status_version_passthrough(self):
        srv = FakeServer()
        srv._status["version"] = "9.9.9"
        r = dispatch(_req({"cmd": "status"}), srv)
        assert r["version"] == "9.9.9"

    def test_status_version_defaults_when_absent(self):
        """A server implementation predating the version key must still
        surface a usable string rather than None/omitting the key."""
        srv = FakeServer()
        del srv._status["version"]
        r = dispatch(_req({"cmd": "status"}), srv)
        assert r["version"] == "0.6.0"

    def test_status_adapter_blocked_passthrough(self):
        srv = FakeServer()
        srv._status["adapter_blocked"] = True
        r = dispatch(_req({"cmd": "status"}), srv)
        assert r["adapter_blocked"] is True

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


class TestDispatchWindow:
    def test_window_start(self):
        srv = FakeServer()
        assert dispatch(_req({"cmd": "window_start"}), srv) == {"ok": True}
        assert srv.window_calls == ["start"]

    @pytest.mark.parametrize("reply,error", [
        ("closing", "window_closing"), ("no_adapter", "no_adapter"),
    ])
    def test_window_start_refusals_use_pinned_errors(self, reply, error):
        srv = FakeServer()
        srv.window_start_result = reply
        assert dispatch(_req({"cmd": "window_start"}), srv) == {"ok": False, "error": error}

    def test_window_stop(self):
        srv = FakeServer()
        assert dispatch(_req({"cmd": "window_stop"}), srv) == {"ok": True}
        srv.window_stop_result = "no_window"
        assert dispatch(_req({"cmd": "window_stop"}), srv) == {"ok": False, "error": "no_window"}

    def test_window_poll_shape(self):
        srv = FakeServer()
        srv._poll.update(state="open", remaining_s=270, adopting=None, devices=[
            {"mac": MAC_A, "name": "Portable CD", "source": "incoming",
             "state": "provisional", "passkey": 123456}])
        r = dispatch(_req({"cmd": "window_poll"}), srv)
        assert r == {"ok": True, "state": "open", "remaining_s": 270, "devices": srv._poll["devices"],
                     "adopting": None, "last_close": None, "last_error": None}
        assert srv.window_calls == ["poll"]

    def test_window_poll_after_close_carries_the_reason(self):
        srv = FakeServer()
        srv._poll.update(last_close={"reason": "paired", "error": None})
        r = dispatch(_req({"cmd": "window_poll"}), srv)
        assert r["state"] == "idle" and r["last_close"] == {"reason": "paired", "error": None}

    @pytest.mark.parametrize("cmd", ["window_start", "window_stop", "window_poll"])
    def test_window_commands_take_no_fields(self, cmd):
        r = dispatch(_req({"cmd": cmd, "extra": 1}), FakeServer())
        assert r == {"ok": False, "error": "unexpected_field"}

    @pytest.mark.parametrize("gone", ["scan_start", "scan_stop", "scan_results", "pair_status"])
    def test_the_scan_commands_are_gone(self, gone):
        assert dispatch(_req({"cmd": gone}), FakeServer()) == {"ok": False, "error": "unknown_cmd"}


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

    @pytest.mark.parametrize("reply,error", [
        ("adopting", "window_adopting"), ("no_window", "no_window"),
        ("unknown_device", "unknown_device"),
    ])
    def test_pair_refusals_use_pinned_errors(self, reply, error):
        """The webui maps these exact strings to HTTP statuses."""
        srv = FakeServer()
        srv.pair_result = reply
        r = dispatch(_req({"cmd": "pair", "mac": MAC_A}), srv)
        assert r == {"ok": False, "error": error}
        assert srv.paired_with == MAC_A


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

    def test_bridge_timeout_maps_to_internal_error(self):
        """A wedged loop (bridge.call_sync raising LoopCallTimeout) must
        reach the client as the same internal_error reply as any other
        handler exception -- never a hang, never a new reply shape."""
        srv = FakeServer(bridge=TimingOutBridge())
        r = dispatch(_req({"cmd": "status"}), srv)
        assert r == {"ok": False, "error": "internal_error"}


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
        window_start=fake.window_start,
        window_stop=fake.window_stop,
        window_poll=fake.window_poll,
        pair=fake.pair,
        forget=fake.forget,
        configure=fake.configure,
        bridge=fake.bridge,
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
            r2 = _send_recv(srv.socket_path, {"cmd": "window_poll"})
            assert r2["ok"] is True and r2["state"] == "idle"
        finally:
            srv.stop()
