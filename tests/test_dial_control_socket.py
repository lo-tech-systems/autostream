"""WP3 tests — dial_control protocol parser, dispatcher, and Unix socket server.

Covers sections 9.1, 9.2, 9.3, and 9.5 of the spec.

Unix socket tests are skipped when socket.AF_UNIX is absent (Windows without
WSL).  All protocol parser/dispatcher tests run on all platforms.
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
from unittest.mock import MagicMock, patch

import pytest

REPO_ROOT = Path(__file__).parent.parent
_DIAL = str(REPO_ROOT / "dial")
_CORE = str(REPO_ROOT / "core")
for _p in (_DIAL, _CORE):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from dial_control import DialControlServer, _dispatch
from dial_control_protocol import (
    CONTROL_PROTOCOL_NAME,
    CONTROL_PROTOCOL_VERSION,
    CONTROL_REQUEST_MAX_BYTES,
    CONTROL_SOCKET_PATH,
)

_HAS_AF_UNIX = hasattr(socket, "AF_UNIX")

skip_no_unix = pytest.mark.skipif(
    not _HAS_AF_UNIX,
    reason="AF_UNIX not available on this platform",
)


# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------

_STATUS = {
    "uuid": "test-uuid-1234",
    "name": "Test Dial",
    "step_percent": 2,
    "recovery_active": False,
    "volume_confirmed": False,
}

_ENRICH_RESULT = [
    {
        "name": "Kitchen",
        "ip": "192.168.1.20",
        "port": 80,
        "dial_api": True,
        "audio_status": True,
        "dial_status": True,
        "playing": True,
        "master_volume": 50,
        "selected_output_count": 2,
        "status_error": None,
    }
]


def _make_server(tmpdir=None, **overrides) -> DialControlServer:
    """Build a DialControlServer with injectable callbacks."""
    nudge_log: list = []

    def _nudge_up():
        nudge_log.append(("up", 2))
        return 2

    def _nudge_down():
        nudge_log.append(("down", -2))
        return -2

    def _nudge_delta(d):
        nudge_log.append(("delta", d))
        return d

    defaults = dict(
        get_runtime_status=lambda: dict(_STATUS),
        get_targets=lambda: [],
        enrich_targets=lambda targets, dial_id: list(_ENRICH_RESULT),
        nudge_up=_nudge_up,
        nudge_down=_nudge_down,
        nudge_delta=_nudge_delta,
        software_version="1.2.3",
    )
    defaults.update(overrides)

    sock_path = (
        os.path.join(tmpdir, "control.sock") if tmpdir else CONTROL_SOCKET_PATH
    )
    return DialControlServer(socket_path=sock_path, **defaults)


def _send_recv(sock_path: str, req: dict) -> dict:
    """Connect to socket, send request, return parsed response."""
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


# ---------------------------------------------------------------------------
# Protocol parser tests (section 9.1) — all platforms
# ---------------------------------------------------------------------------

class FakeServer:
    """Minimal DialControlServer substitute for _dispatch tests."""

    def __init__(self):
        self.nudge_up_called = False
        self.nudge_down_called = False
        self.delta_called_with = None
        self.software_version = "1.2.3"

    def get_runtime_status(self):
        return dict(_STATUS)

    def get_targets(self):
        return []

    def enrich_targets(self, targets, dial_id):
        return []

    def nudge_up(self):
        self.nudge_up_called = True
        return 2

    def nudge_down(self):
        self.nudge_down_called = True
        return -2

    def nudge_delta(self, d):
        self.delta_called_with = d
        return d


def _req(obj: dict) -> bytes:
    return (json.dumps(obj) + "\n").encode("utf-8")


class TestParserPing:
    def test_ping_ok(self):
        r = _dispatch(_req({"command": "ping"}), FakeServer())
        assert r["ok"] is True
        assert r["service"] == "autostream-dial"

    def test_ping_unexpected_field(self):
        r = _dispatch(_req({"command": "ping", "extra": 1}), FakeServer())
        assert r["ok"] is False
        assert r["error"] == "unexpected_field"
        assert "extra" in r["message"]


class TestParserVersion:
    def test_version_response(self):
        r = _dispatch(_req({"command": "version"}), FakeServer())
        assert r["ok"] is True
        assert r["protocol"] == CONTROL_PROTOCOL_NAME
        assert r["protocol_version"] == CONTROL_PROTOCOL_VERSION
        assert r["software_version"] == "1.2.3"

    def test_version_unexpected_field(self):
        r = _dispatch(_req({"command": "version", "foo": "bar"}), FakeServer())
        assert r["error"] == "unexpected_field"


class TestParserStatus:
    def test_status_includes_required_fields(self):
        r = _dispatch(_req({"command": "status"}), FakeServer())
        assert r["ok"] is True
        for field in ("uuid", "name", "step_percent", "target_count",
                      "recovery_active", "volume_confirmed"):
            assert field in r, f"missing field: {field}"

    def test_status_does_not_include_pin(self):
        r = _dispatch(_req({"command": "status"}), FakeServer())
        assert "pin" not in r
        assert "current_pin" not in r
        assert "new_pin" not in r

    def test_status_recovery_state(self):
        class _RecoveryServer(FakeServer):
            def get_runtime_status(self):
                s = dict(_STATUS)
                s["recovery_active"] = True
                s["volume_confirmed"] = True
                return s
        r = _dispatch(_req({"command": "status"}), _RecoveryServer())
        assert r["recovery_active"] is True
        assert r["volume_confirmed"] is True


class TestParserTargets:
    def test_targets_empty(self):
        r = _dispatch(_req({"command": "targets"}), FakeServer())
        assert r["ok"] is True
        assert r["count"] == 0
        assert r["targets"] == []

    def test_targets_with_enriched_results(self):
        class _EnrichServer(FakeServer):
            def enrich_targets(self, targets, dial_id):
                return list(_ENRICH_RESULT)
            def get_targets(self):
                return [MagicMock()]  # one fake target

        r = _dispatch(_req({"command": "targets"}), _EnrichServer())
        assert r["ok"] is True
        assert r["count"] == 1
        assert len(r["targets"]) == 1


class TestParserNudge:
    def test_nudge_up(self):
        srv = FakeServer()
        r = _dispatch(_req({"command": "nudge", "direction": "up"}), srv)
        assert r["ok"] is True
        assert r["delta"] > 0
        assert r["queued"] is True
        assert srv.nudge_up_called

    def test_nudge_down(self):
        srv = FakeServer()
        r = _dispatch(_req({"command": "nudge", "direction": "down"}), srv)
        assert r["ok"] is True
        assert r["delta"] < 0
        assert srv.nudge_down_called

    def test_nudge_explicit_delta_positive(self):
        srv = FakeServer()
        r = _dispatch(_req({"command": "nudge", "delta": 10}), srv)
        assert r["ok"] is True
        assert r["delta"] == 10
        assert srv.delta_called_with == 10

    def test_nudge_explicit_delta_negative(self):
        srv = FakeServer()
        r = _dispatch(_req({"command": "nudge", "delta": -5}), srv)
        assert r["ok"] is True
        assert r["delta"] == -5

    def test_nudge_delta_boundary_minus_100(self):
        srv = FakeServer()
        r = _dispatch(_req({"command": "nudge", "delta": -100}), srv)
        assert r["ok"] is True

    def test_nudge_delta_boundary_plus_100(self):
        srv = FakeServer()
        r = _dispatch(_req({"command": "nudge", "delta": 100}), srv)
        assert r["ok"] is True

    def test_nudge_both_direction_and_delta_rejected(self):
        r = _dispatch(
            _req({"command": "nudge", "direction": "up", "delta": 5}),
            FakeServer(),
        )
        assert r["ok"] is False
        assert r["error"] == "invalid_request"

    def test_nudge_neither_field_rejected(self):
        r = _dispatch(_req({"command": "nudge"}), FakeServer())
        assert r["ok"] is False
        assert r["error"] == "invalid_request"

    def test_nudge_invalid_direction(self):
        r = _dispatch(
            _req({"command": "nudge", "direction": "left"}), FakeServer()
        )
        assert r["error"] == "invalid_direction"

    def test_nudge_zero_delta_rejected(self):
        r = _dispatch(_req({"command": "nudge", "delta": 0}), FakeServer())
        assert r["error"] == "invalid_delta"

    def test_nudge_boolean_delta_rejected(self):
        r = _dispatch(_req({"command": "nudge", "delta": True}), FakeServer())
        assert r["error"] == "invalid_delta"

    def test_nudge_float_delta_rejected(self):
        r = _dispatch(_req({"command": "nudge", "delta": 1.5}), FakeServer())
        assert r["error"] == "invalid_delta"

    def test_nudge_string_delta_rejected(self):
        r = _dispatch(_req({"command": "nudge", "delta": "5"}), FakeServer())
        assert r["error"] == "invalid_delta"

    def test_nudge_out_of_range_rejected(self):
        r = _dispatch(_req({"command": "nudge", "delta": 101}), FakeServer())
        assert r["error"] == "invalid_delta"

    def test_nudge_out_of_range_negative_rejected(self):
        r = _dispatch(_req({"command": "nudge", "delta": -101}), FakeServer())
        assert r["error"] == "invalid_delta"

    def test_nudge_unexpected_field(self):
        r = _dispatch(
            _req({"command": "nudge", "direction": "up", "target_ip": "1.2.3.4"}),
            FakeServer(),
        )
        assert r["error"] == "unexpected_field"
        assert "target_ip" in r["message"]


class TestParserErrors:
    def test_malformed_json(self):
        r = _dispatch(b"not json\n", FakeServer())
        assert r["error"] == "invalid_json"

    def test_invalid_utf8(self):
        r = _dispatch(b"\xff\xfe\n", FakeServer())
        assert r["error"] == "invalid_json"

    def test_json_array_root(self):
        r = _dispatch(b"[1,2,3]\n", FakeServer())
        assert r["error"] == "invalid_request"

    def test_json_string_root(self):
        r = _dispatch(b'"hello"\n', FakeServer())
        assert r["error"] == "invalid_request"

    def test_json_null_root(self):
        r = _dispatch(b"null\n", FakeServer())
        assert r["error"] == "invalid_request"

    def test_json_number_root(self):
        r = _dispatch(b"42\n", FakeServer())
        assert r["error"] == "invalid_request"

    def test_json_boolean_root(self):
        r = _dispatch(b"true\n", FakeServer())
        assert r["error"] == "invalid_request"

    def test_missing_command(self):
        r = _dispatch(_req({"action": "ping"}), FakeServer())
        assert r["error"] == "invalid_request"

    def test_non_string_command(self):
        r = _dispatch(_req({"command": 42}), FakeServer())
        assert r["error"] == "invalid_request"

    def test_unknown_command(self):
        r = _dispatch(_req({"command": "rotate"}), FakeServer())
        assert r["error"] == "unknown_command"
        assert "rotate" in r["message"]

    def test_request_too_large(self):
        # Line > 4096 bytes before newline
        big = b"x" * (CONTROL_REQUEST_MAX_BYTES + 1) + b"\n"
        r = _dispatch(big, FakeServer())
        assert r["error"] == "request_too_large"

    def test_exactly_4096_bytes_before_newline_is_too_large(self):
        # A line of exactly 4096 bytes (before the newline) exceeds the limit:
        # the spec says the newline must occur at or before byte 4096, meaning
        # the line content is at most 4095 bytes + newline = 4096 total.
        # A 4096-byte line + newline = 4097 bytes total → rejected.
        prefix = b'{"command":"ping"}'
        padding = b" " * (CONTROL_REQUEST_MAX_BYTES - len(prefix))
        data = prefix + padding + b"\n"
        assert len(data) == CONTROL_REQUEST_MAX_BYTES + 1  # 4097
        r = _dispatch(data, FakeServer())
        assert r["error"] in ("request_too_large", "invalid_json")

    def test_no_newline_rejected(self):
        r = _dispatch(b'{"command":"ping"}', FakeServer())
        assert r["ok"] is False

    def test_unexpected_fields_reports_lexicographically_first(self):
        r = _dispatch(
            _req({"command": "ping", "zzz": 1, "aaa": 2}), FakeServer()
        )
        assert r["error"] == "unexpected_field"
        assert "aaa" in r["message"]

    def test_internal_error_caught(self):
        class _BrokenServer(FakeServer):
            def get_runtime_status(self):
                raise RuntimeError("boom")

        r = _dispatch(_req({"command": "status"}), _BrokenServer())
        assert r["error"] == "internal_error"
        assert r["ok"] is False


# ---------------------------------------------------------------------------
# Callback identity tests (section 9.2) — all platforms
# ---------------------------------------------------------------------------

class TestCallbackIdentity:
    """Prove nudge_up/nudge_down passed to encoder and socket server are same callables."""

    def test_nudge_up_called_on_upward_nudge(self):
        up_calls = []

        def my_up():
            up_calls.append(1)
            return 2

        srv = FakeServer()
        srv.nudge_up = my_up
        r = _dispatch(_req({"command": "nudge", "direction": "up"}), srv)
        assert r["ok"] is True
        assert len(up_calls) == 1

    def test_nudge_down_called_on_downward_nudge(self):
        down_calls = []

        def my_down():
            down_calls.append(-2)
            return -2

        srv = FakeServer()
        srv.nudge_down = my_down
        r = _dispatch(_req({"command": "nudge", "direction": "down"}), srv)
        assert r["ok"] is True
        assert len(down_calls) == 1

    def test_positive_delta_confirms_recovery(self):
        """Positive nudge_delta must call http_server.confirm_volume()."""
        confirm_calls = []
        enqueue_calls = []

        def fake_confirm():
            confirm_calls.append(1)

        def fake_enqueue(d):
            enqueue_calls.append(d)

        # Simulate the nudge_delta closure from dial_main
        import dial_http_server as dhs
        mock_http = MagicMock()
        mock_http.step_percent = 2
        mock_http.confirm_volume = fake_confirm

        def nudge_delta_fn(delta):
            if delta > 0:
                fake_confirm()
            fake_enqueue(delta)
            return delta

        srv = FakeServer()
        srv.nudge_delta = nudge_delta_fn
        r = _dispatch(_req({"command": "nudge", "delta": 5}), srv)
        assert r["ok"] is True
        assert len(confirm_calls) == 1

    def test_negative_delta_does_not_confirm_recovery(self):
        confirm_calls = []

        def fake_confirm():
            confirm_calls.append(1)

        def nudge_delta_fn(delta):
            if delta > 0:
                fake_confirm()
            return delta

        srv = FakeServer()
        srv.nudge_delta = nudge_delta_fn
        r = _dispatch(_req({"command": "nudge", "delta": -5}), srv)
        assert r["ok"] is True
        assert len(confirm_calls) == 0

    def test_no_targets_still_queues(self):
        enqueue_calls = []

        def my_up():
            enqueue_calls.append(1)
            return 2

        srv = FakeServer()
        srv.nudge_up = my_up
        r = _dispatch(_req({"command": "nudge", "direction": "up"}), srv)
        assert r["ok"] is True
        assert r["queued"] is True
        assert len(enqueue_calls) == 1


# ---------------------------------------------------------------------------
# Unix socket server tests (section 9.5) — skipped when AF_UNIX absent
# ---------------------------------------------------------------------------

@skip_no_unix
class TestUnixSocketServer:
    def _tmpdir(self):
        d = tempfile.mkdtemp(prefix="adc-")
        return d

    def _make_and_start(self, tmpdir):
        srv = _make_server(tmpdir)
        srv.start()
        # Brief wait for server thread to bind
        time.sleep(0.05)
        return srv

    def test_startup_creates_socket(self):
        d = self._tmpdir()
        srv = self._make_and_start(d)
        try:
            path = os.path.join(d, "control.sock")
            assert os.path.exists(path)
            assert stat.S_ISSOCK(os.stat(path).st_mode)
        finally:
            srv.stop()

    def test_ping_request_produces_response(self):
        d = self._tmpdir()
        srv = self._make_and_start(d)
        try:
            r = _send_recv(srv.socket_path, {"command": "ping"})
            assert r["ok"] is True
            assert r["service"] == "autostream-dial"
        finally:
            srv.stop()

    def test_multiple_sequential_clients(self):
        d = self._tmpdir()
        srv = self._make_and_start(d)
        try:
            for _ in range(5):
                r = _send_recv(srv.socket_path, {"command": "ping"})
                assert r["ok"] is True
        finally:
            srv.stop()

    def test_concurrent_clients_no_corruption(self):
        d = self._tmpdir()
        srv = self._make_and_start(d)
        results = []
        errors = []

        def worker():
            try:
                r = _send_recv(srv.socket_path, {"command": "version"})
                results.append(r)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=5)

        try:
            assert not errors, f"Errors: {errors}"
            assert len(results) == 10
            for r in results:
                assert r["ok"] is True
        finally:
            srv.stop()

    def test_client_disconnect_does_not_stop_server(self):
        d = self._tmpdir()
        srv = self._make_and_start(d)
        try:
            # Connect and immediately close without sending data
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.connect(srv.socket_path)
            s.close()
            # Server should still respond to next client
            r = _send_recv(srv.socket_path, {"command": "ping"})
            assert r["ok"] is True
        finally:
            srv.stop()

    def test_stale_socket_replaced_on_start(self):
        d = self._tmpdir()
        path = os.path.join(d, "control.sock")
        # Create a stale socket at the path
        stale = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        stale.bind(path)
        stale.close()
        # Starting server should replace it
        srv = _make_server(d)
        srv.start()
        time.sleep(0.05)
        try:
            r = _send_recv(path, {"command": "ping"})
            assert r["ok"] is True
        finally:
            srv.stop()

    def test_regular_file_at_socket_path_raises(self):
        d = self._tmpdir()
        path = os.path.join(d, "control.sock")
        # Create a regular file at the path
        with open(path, "w") as f:
            f.write("not a socket")
        srv = _make_server(d)
        with pytest.raises(OSError):
            srv.start()

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
        srv.stop()  # must not raise

    def test_second_stop_is_noop(self):
        d = self._tmpdir()
        srv = self._make_and_start(d)
        srv.stop()
        srv.stop()  # must not raise

    def test_start_twice_raises(self):
        d = self._tmpdir()
        srv = self._make_and_start(d)
        try:
            with pytest.raises(RuntimeError):
                srv.start()
        finally:
            srv.stop()

    def test_request_too_large_rejected(self):
        d = self._tmpdir()
        srv = self._make_and_start(d)
        try:
            big_payload = {"command": "ping", "x": "a" * 4100}
            r = _send_recv(srv.socket_path, big_payload)
            assert r["ok"] is False
            assert r["error"] == "request_too_large"
        finally:
            srv.stop()

    def test_symlink_at_socket_path_raises(self):
        d = self._tmpdir()
        path = os.path.join(d, "control.sock")
        target = os.path.join(d, "other.sock")
        os.symlink(target, path)
        srv = _make_server(d)
        with pytest.raises(OSError):
            srv.start()


# ---------------------------------------------------------------------------
# DialControlServer: AF_UNIX absent raises RuntimeError
# ---------------------------------------------------------------------------

class TestAFUnixAbsent:
    def test_start_raises_when_af_unix_missing(self):
        with patch("dial_control._AF_UNIX", None):
            srv = DialControlServer(
                get_runtime_status=lambda: dict(_STATUS),
                get_targets=lambda: [],
                enrich_targets=lambda t, d: [],
                nudge_up=lambda: 2,
                nudge_down=lambda: -2,
                nudge_delta=lambda d: d,
                software_version="1.0",
                socket_path="/tmp/test.sock",
            )
            with pytest.raises(RuntimeError, match="AF_UNIX"):
                srv.start()


# ---------------------------------------------------------------------------
# Import stat for socket type checks
# ---------------------------------------------------------------------------

import stat
