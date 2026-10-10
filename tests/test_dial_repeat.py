"""Tests for dial_repeat.py — the repeat/replay transport and arm sender.

Covers: request shape (path, method, JSON body) for both transport and arm
sends, the dial_id stamped onto every body, the fixed send timeout, that a
redirect status is reported as-is (never followed), that any exception
degrades to (None, None), a non-JSON/non-object response body degrading to
a None body, the enqueue helpers' queue item shape, the worker loop calling
on_result for each event and surviving a raising callback, and that this
module never imports dial_volume (a separate worker by design).
"""
from __future__ import annotations

import json
import sys
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

import dial_repeat as dr
from dial_repeat import (
    REPEAT_SEND_TIMEOUT_S,
    _RepeatTarget,
    _send_one,
    enqueue_arm,
    enqueue_transport,
    start_repeat_worker,
)


def _target(appliance_id="a" * 20, ip="10.0.0.5", port=8080) -> _RepeatTarget:
    return _RepeatTarget(appliance_id=appliance_id, ip=ip, port=port)


class _FakeHTTPConn:
    """Minimal mock of http.client.HTTPConnection, mirroring the one
    test_dial_target_status.py uses for the same purpose."""

    def __init__(self, response_data: bytes, status: int = 200):
        self._data = response_data
        self._status = status
        self.request_called_with: dict | None = None
        self.closed = False

    def request(self, method, url, body=None, headers=None):
        self.request_called_with = {
            "method": method, "url": url, "body": body, "headers": headers,
        }

    def getresponse(self):
        resp = MagicMock()
        resp.status = self._status
        data = self._data

        def _read(n=None):
            return data if n is None else data[:n]

        resp.read = MagicMock(side_effect=_read)
        return resp

    def close(self):
        self.closed = True


def _mock_conn(data, status: int = 200):
    """Patch dial_repeat.http.client.HTTPConnection to return *data*
    (a dict, encoded as JSON, or raw bytes) at *status*. Returns the patch
    context manager; the constructed connection instances are appended to
    the returned list so a test can inspect the request that was made."""
    raw = json.dumps(data).encode("utf-8") if isinstance(data, dict) else data
    instances: list[_FakeHTTPConn] = []

    class _Conn(_FakeHTTPConn):
        def __init__(self, host, port=None, timeout=None):
            super().__init__(raw, status)
            self.host = host
            self.port = port
            self.timeout = timeout
            instances.append(self)

    return patch("dial_repeat.http.client.HTTPConnection", _Conn), instances


class _RaisingConn:
    def __init__(self, host, port=None, timeout=None):
        pass

    def request(self, *a, **kw):
        raise OSError("connection refused")

    def close(self):
        pass


# ---------------------------------------------------------------------------
# _send_one: request shape, timeout, redirects, failure degradation
# ---------------------------------------------------------------------------

class TestSendOneRequestShape:
    def setup_method(self):
        dr._cfg = MagicMock(uuid="dial-uuid")

    def teardown_method(self):
        dr._cfg = None

    def test_transport_path_and_body(self):
        patcher, instances = _mock_conn({"ok": True, "state": "replaying", "armed": True,
                                          "position_seconds": 0.0})
        with patcher:
            status, body = _send_one(
                "/api/dial/repeat", _target(), {"action": "seek", "position_seconds": 0.0},
            )
        assert status == 200
        assert body == {"ok": True, "state": "replaying", "armed": True, "position_seconds": 0.0}
        req = instances[0].request_called_with
        assert req["method"] == "POST"
        assert req["url"] == "/api/dial/repeat"
        sent = json.loads(req["body"])
        assert sent == {"action": "seek", "position_seconds": 0.0, "dial_id": "dial-uuid"}
        assert req["headers"]["Content-Type"] == "application/json"

    def test_arm_path_and_body(self):
        patcher, instances = _mock_conn({"ok": True, "state": "hold", "armed": True,
                                          "position_seconds": 0.0})
        with patcher:
            status, body = _send_one("/api/dial/repeat/arm", _target(), {"armed": True})
        assert status == 200
        req = instances[0].request_called_with
        assert req["url"] == "/api/dial/repeat/arm"
        sent = json.loads(req["body"])
        assert sent == {"armed": True, "dial_id": "dial-uuid"}

    def test_connection_uses_target_host_port_and_fixed_timeout(self):
        patcher, instances = _mock_conn({"ok": True})
        target = _target(ip="192.168.1.42", port=9001)
        with patcher:
            _send_one("/api/dial/repeat", target, {"action": "stop", "position_seconds": 0.0})
        assert instances[0].host == "192.168.1.42"
        assert instances[0].port == 9001
        assert instances[0].timeout == REPEAT_SEND_TIMEOUT_S
        assert REPEAT_SEND_TIMEOUT_S == 2.0

    def test_connection_always_closed(self):
        patcher, instances = _mock_conn({"ok": True})
        with patcher:
            _send_one("/api/dial/repeat", _target(), {"action": "stop", "position_seconds": 0.0})
        assert instances[0].closed is True

    def test_dial_id_defaults_empty_when_no_cfg(self):
        dr._cfg = None
        patcher, instances = _mock_conn({"ok": True})
        with patcher:
            _send_one("/api/dial/repeat", _target(), {"action": "stop", "position_seconds": 0.0})
        sent = json.loads(instances[0].request_called_with["body"])
        assert sent["dial_id"] == ""


class TestSendOneOutcomes:
    def setup_method(self):
        dr._cfg = MagicMock(uuid="dial-uuid")

    def teardown_method(self):
        dr._cfg = None

    def test_redirect_status_reported_not_followed(self):
        """A 302 (an old appliance's nginx redirecting to an offline page)
        must be reported as its real status, never silently followed and
        read as a 200."""
        patcher, instances = _mock_conn(b"<html>redirecting</html>", status=302)
        with patcher:
            status, body = _send_one("/api/dial/repeat", _target(), {"action": "stop", "position_seconds": 0.0})
        assert status == 302
        assert body is None
        assert len(instances) == 1  # exactly one connection: no redirect chase

    def test_non_json_body_is_none(self):
        patcher, _ = _mock_conn(b"not json at all", status=200)
        with patcher:
            status, body = _send_one("/api/dial/repeat", _target(), {"action": "stop", "position_seconds": 0.0})
        assert status == 200
        assert body is None

    def test_non_object_json_body_is_none(self):
        patcher, _ = _mock_conn(b"[1, 2, 3]", status=200)
        with patcher:
            status, body = _send_one("/api/dial/repeat", _target(), {"action": "stop", "position_seconds": 0.0})
        assert status == 200
        assert body is None

    def test_exception_never_raises_and_returns_none_none(self):
        with patch("dial_repeat.http.client.HTTPConnection", _RaisingConn):
            status, body = _send_one("/api/dial/repeat", _target(), {"action": "stop", "position_seconds": 0.0})
        assert status is None
        assert body is None

    def test_ok_false_body_still_parsed(self):
        patcher, _ = _mock_conn({"ok": False, "error": "source_active", "state": "recording", "armed": False})
        with patcher:
            status, body = _send_one("/api/dial/repeat", _target(), {"action": "seek", "position_seconds": 0.0})
        assert status == 200
        assert body == {"ok": False, "error": "source_active", "state": "recording", "armed": False}

    def test_read_capped_at_max_response_bytes(self):
        """The response read is bounded — a well-formed but enormous body
        is simply truncated (and likely fails JSON parsing), never read in
        full into memory."""
        huge = b'{"ok": true, "pad": "' + b"x" * 200_000 + b'"}'
        patcher, _ = _mock_conn(huge, status=200)
        with patcher:
            status, body = _send_one("/api/dial/repeat", _target(), {"action": "stop", "position_seconds": 0.0})
        assert status == 200
        # Truncated mid-body: not valid JSON any more.
        assert body is None


# ---------------------------------------------------------------------------
# enqueue_transport / enqueue_arm: queue item shape, no I/O, no lock
# ---------------------------------------------------------------------------

class TestEnqueue:
    def test_enqueue_transport_puts_kind_target_and_payload(self):
        target = _target()
        enqueue_transport(target, "seek", 12.5, 3.5)
        kind, put_target, payload = dr._queue.get_nowait()
        assert kind == "transport"
        assert put_target is target
        assert payload == {"action": "seek", "position_seconds": 12.5, "token": 3.5}

    def test_enqueue_transport_coerces_position_to_float(self):
        enqueue_transport(_target(), "stop", 0, 1.0)
        _, _, payload = dr._queue.get_nowait()
        assert payload["position_seconds"] == 0.0
        assert isinstance(payload["position_seconds"], float)

    def test_enqueue_arm_puts_kind_target_and_payload(self):
        target = _target()
        enqueue_arm(target, True, 3.5)
        kind, put_target, payload = dr._queue.get_nowait()
        assert kind == "arm"
        assert put_target is target
        assert payload == {"armed": True, "token": 3.5}

    def test_enqueue_arm_coerces_to_bool(self):
        enqueue_arm(_target(), 1, 1.0)
        _, _, payload = dr._queue.get_nowait()
        assert payload["armed"] is True


# ---------------------------------------------------------------------------
# The worker loop: start_repeat_worker, on_result dispatch, survives a
# raising callback.
# ---------------------------------------------------------------------------

class TestWorker:
    def test_worker_sends_and_calls_on_result(self):
        results = []
        done = threading.Event()

        def on_result(kind, appliance_id, status, body, request):
            results.append((kind, appliance_id, status, body, request))
            done.set()

        patcher, _ = _mock_conn({"ok": True, "state": "replaying", "armed": True, "position_seconds": 0.0})
        cfg = MagicMock(uuid="dial-uuid")
        with patcher:
            start_repeat_worker(cfg, on_result=on_result)
            enqueue_transport(_target(appliance_id="b" * 20), "seek", 0.0, 6.25)
            assert done.wait(timeout=2.0)

        assert len(results) == 1
        kind, appliance_id, status, body, request = results[0]
        assert kind == "transport"
        assert appliance_id == "b" * 20
        assert status == 200
        assert body["ok"] is True
        assert request == {"action": "seek", "position_seconds": 0.0, "token": 6.25}

    def test_the_token_is_stripped_before_the_wire_and_given_to_the_callback(self):
        results = []
        done = threading.Event()

        def on_result(kind, appliance_id, status, body, request):
            results.append((kind, request))
            done.set()

        patcher, instances = _mock_conn({"ok": True, "state": "hold", "armed": True, "position_seconds": 0.0})
        cfg = MagicMock(uuid="dial-uuid")
        with patcher:
            start_repeat_worker(cfg, on_result=on_result)
            enqueue_arm(_target(appliance_id="g" * 20), True, 8.75)
            assert done.wait(timeout=2.0)

        wire = json.loads(instances[0].request_called_with["body"])
        assert "token" not in wire
        assert wire["armed"] is True
        assert results == [("arm", {"armed": True, "token": 8.75})]

    def test_worker_calls_on_result_for_arm(self):
        results = []
        done = threading.Event()

        def on_result(kind, appliance_id, status, body, request):
            results.append(kind)
            done.set()

        patcher, _ = _mock_conn({"ok": True, "state": "hold", "armed": True, "position_seconds": 0.0})
        cfg = MagicMock(uuid="dial-uuid")
        with patcher:
            start_repeat_worker(cfg, on_result=on_result)
            enqueue_arm(_target(appliance_id="c" * 20), True, 1.0)
            assert done.wait(timeout=2.0)

        assert results == ["arm"]

    def test_worker_survives_a_raising_callback_and_keeps_processing(self):
        calls = []
        second_done = threading.Event()

        def on_result(kind, appliance_id, status, body, request):
            calls.append(appliance_id)
            if len(calls) == 2:
                second_done.set()
            if len(calls) == 1:
                raise RuntimeError("callback boom")

        patcher, _ = _mock_conn({"ok": True, "state": "hold", "armed": False, "position_seconds": 0.0})
        cfg = MagicMock(uuid="dial-uuid")
        with patcher:
            start_repeat_worker(cfg, on_result=on_result)
            enqueue_transport(_target(appliance_id="d" * 20), "stop", 0.0, 1.0)
            enqueue_transport(_target(appliance_id="e" * 20), "stop", 0.0, 2.0)
            assert second_done.wait(timeout=2.0)

        assert calls == ["d" * 20, "e" * 20]

    def test_worker_runs_with_no_on_result_at_all(self):
        """on_result is optional — a worker started without one must still
        drain the queue without raising."""
        patcher, _ = _mock_conn({"ok": True, "state": "hold", "armed": False, "position_seconds": 0.0})
        cfg = MagicMock(uuid="dial-uuid")
        with patcher:
            start_repeat_worker(cfg, on_result=None)
            enqueue_transport(_target(appliance_id="f" * 20), "stop", 0.0, 1.0)
            # No synchronisation point without a callback — just give the
            # worker a moment and confirm the queue drains.
            deadline = time.monotonic() + 2.0
            while not dr._queue.empty() and time.monotonic() < deadline:
                time.sleep(0.01)
        assert dr._queue.empty()


# ---------------------------------------------------------------------------
# Module isolation: dial_repeat is its own worker, never dial_volume's.
# ---------------------------------------------------------------------------

class TestModuleIsolation:
    def test_dial_volume_never_imported_by_dial_repeat(self):
        assert "dial_volume" not in dr.__dict__
        source = Path(dr.__file__).read_text(encoding="utf-8")
        assert "import dial_volume" not in source

    def test_never_uses_urllib(self):
        """This module uses http.client, matching the invariant that new
        dial HTTP uses a fixed-timeout http.client connection, never
        urllib."""
        source = Path(dr.__file__).read_text(encoding="utf-8")
        assert "urllib" not in source
