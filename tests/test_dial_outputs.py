"""Tests for dial_outputs.py — the per-output list/enable/volume sender.

Covers: request shape (path, method, JSON body) for both a list fetch and
an output mutation, the dial_id stamped onto every body, the fixed send
timeout, that a redirect status is reported as-is (never followed), that
any exception degrades to (None, None), a non-JSON/non-object response
body degrading to a None body, the enqueue helpers' queue item shape, the
worker loop calling on_result for each event, the automatic fetch-after-
set reconciliation, fetch coalescing (a fetch already queued for a target
is not duplicated), surviving a raising callback, and that this module is
its own worker, never dial_display's or dial_repeat's.
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

import dial_outputs as do
from dial_outputs import (
    OUTPUTS_SEND_TIMEOUT_S,
    _OutputsTarget,
    _send_one,
    enqueue_fetch,
    enqueue_set,
    start_outputs_worker,
)


def _target(appliance_id="a" * 20, ip="10.0.0.5", port=8080) -> _OutputsTarget:
    return _OutputsTarget(appliance_id=appliance_id, ip=ip, port=port)


class _FakeHTTPConn:
    """Minimal mock of http.client.HTTPConnection, mirroring the one
    test_dial_repeat.py uses for the same purpose."""

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
    """Patch dial_outputs.http.client.HTTPConnection to return *data*
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

    return patch("dial_outputs.http.client.HTTPConnection", _Conn), instances


class _RaisingConn:
    def __init__(self, host, port=None, timeout=None):
        pass

    def request(self, *a, **kw):
        raise OSError("connection refused")

    def close(self):
        pass


class _OnePass(BaseException):
    pass


def _run_worker_once(items):
    """Run the worker loop over *items* on this thread, then stop it. The
    shared queue and the worker threads other tests leave parked on it are
    not touched."""
    pending = list(items)

    class _Items:
        def get(self):
            if not pending:
                raise _OnePass()
            return pending.pop(0)

    with patch.object(do, "_queue", _Items()), patch.object(do, "enqueue_fetch"):
        try:
            do._worker()
        except _OnePass:
            pass


def _drain_queue():
    """Empty dial_outputs._queue and clear pending-fetch bookkeeping so
    tests never see leftovers from a previous test."""
    try:
        while True:
            do._queue.get_nowait()
    except Exception:
        pass
    with do._pending_fetch_lock:
        do._pending_fetch_ids.clear()


@pytest.fixture(autouse=True)
def _clean_queue():
    _drain_queue()
    yield
    _drain_queue()


# ---------------------------------------------------------------------------
# _send_one: request shape, timeout, redirects, failure degradation
# ---------------------------------------------------------------------------

class TestSendOneRequestShape:
    def setup_method(self):
        do._cfg = MagicMock(uuid="dial-uuid")

    def teardown_method(self):
        do._cfg = None

    def test_fetch_path_and_empty_body(self):
        patcher, instances = _mock_conn({"ok": True, "outputs": [], "appliance_id": "x"})
        with patcher:
            status, body = _send_one("/api/dial/outputs", _target(), {})
        assert status == 200
        assert body == {"ok": True, "outputs": [], "appliance_id": "x"}
        req = instances[0].request_called_with
        assert req["method"] == "POST"
        assert req["url"] == "/api/dial/outputs"
        sent = json.loads(req["body"])
        assert sent == {"dial_id": "dial-uuid"}
        assert req["headers"]["Content-Type"] == "application/json"

    def test_a_set_uses_the_longer_timeout_and_a_fetch_the_short_one(self):
        patcher, instances = _mock_conn({"ok": True})
        with patcher:
            _run_worker_once([("fetch", _target(), {}), ("set", _target(), {"id": "1"})])
        assert do.OUTPUTS_SET_TIMEOUT_S == 10.0 and do.OUTPUTS_SEND_TIMEOUT_S == 2.0
        by_path = {i.request_called_with["url"]: i.timeout for i in instances}
        assert by_path["/api/dial/outputs"] == 2.0
        assert by_path["/api/dial/outputs/set"] == 10.0

    def test_send_one_defaults_to_the_short_timeout(self):
        patcher, instances = _mock_conn({"ok": True})
        with patcher:
            _send_one("/api/dial/outputs", _target(), {})
        assert instances[0].timeout == OUTPUTS_SEND_TIMEOUT_S

    def test_set_path_and_body(self):
        patcher, instances = _mock_conn({"ok": True, "id": "1"})
        with patcher:
            status, body = _send_one(
                "/api/dial/outputs/set", _target(), {"id": "1", "selected": True, "volume": 42},
            )
        assert status == 200
        req = instances[0].request_called_with
        assert req["url"] == "/api/dial/outputs/set"
        sent = json.loads(req["body"])
        assert sent == {"id": "1", "selected": True, "volume": 42, "dial_id": "dial-uuid"}

    def test_connection_uses_target_host_port_and_fixed_timeout(self):
        patcher, instances = _mock_conn({"ok": True})
        target = _target(ip="192.168.1.42", port=9001)
        with patcher:
            _send_one("/api/dial/outputs", target, {})
        assert instances[0].host == "192.168.1.42"
        assert instances[0].port == 9001
        assert instances[0].timeout == OUTPUTS_SEND_TIMEOUT_S
        assert OUTPUTS_SEND_TIMEOUT_S == 2.0

    def test_connection_always_closed(self):
        patcher, instances = _mock_conn({"ok": True})
        with patcher:
            _send_one("/api/dial/outputs", _target(), {})
        assert instances[0].closed is True

    def test_dial_id_defaults_empty_when_no_cfg(self):
        do._cfg = None
        patcher, instances = _mock_conn({"ok": True})
        with patcher:
            _send_one("/api/dial/outputs", _target(), {})
        sent = json.loads(instances[0].request_called_with["body"])
        assert sent["dial_id"] == ""


class TestSendOneOutcomes:
    def setup_method(self):
        do._cfg = MagicMock(uuid="dial-uuid")

    def teardown_method(self):
        do._cfg = None

    def test_redirect_status_reported_not_followed(self):
        patcher, instances = _mock_conn(b"<html>redirecting</html>", status=302)
        with patcher:
            status, body = _send_one("/api/dial/outputs", _target(), {})
        assert status == 302
        assert body is None
        assert len(instances) == 1

    def test_412_status_reported_with_body(self):
        patcher, _ = _mock_conn(
            {"ok": False, "error": "dial_not_authorized", "appliance_id": "x"}, status=412,
        )
        with patcher:
            status, body = _send_one("/api/dial/outputs", _target(), {})
        assert status == 412
        assert body == {"ok": False, "error": "dial_not_authorized", "appliance_id": "x"}

    def test_non_json_body_is_none(self):
        patcher, _ = _mock_conn(b"not json at all", status=200)
        with patcher:
            status, body = _send_one("/api/dial/outputs", _target(), {})
        assert status == 200
        assert body is None

    def test_non_object_json_body_is_none(self):
        patcher, _ = _mock_conn(b"[1, 2, 3]", status=200)
        with patcher:
            status, body = _send_one("/api/dial/outputs", _target(), {})
        assert status == 200
        assert body is None

    def test_exception_never_raises_and_returns_none_none(self):
        with patch("dial_outputs.http.client.HTTPConnection", _RaisingConn):
            status, body = _send_one("/api/dial/outputs", _target(), {})
        assert status is None
        assert body is None

    def test_read_capped_at_max_response_bytes(self):
        huge = b'{"ok": true, "pad": "' + b"x" * 200_000 + b'"}'
        patcher, _ = _mock_conn(huge, status=200)
        with patcher:
            status, body = _send_one("/api/dial/outputs", _target(), {})
        assert status == 200
        assert body is None


# ---------------------------------------------------------------------------
# enqueue_fetch / enqueue_set: queue item shape, no I/O, coalescing
# ---------------------------------------------------------------------------

class TestEnqueue:
    def test_enqueue_fetch_puts_kind_target_and_empty_payload(self):
        target = _target()
        enqueue_fetch(target)
        kind, put_target, payload = do._queue.get_nowait()
        assert kind == "fetch"
        assert put_target is target
        assert payload == {}

    def test_enqueue_set_puts_kind_target_and_body(self):
        target = _target()
        enqueue_set(target, "1", selected=True, volume=55, token=3.5)
        kind, put_target, payload = do._queue.get_nowait()
        assert kind == "set"
        assert put_target is target
        assert payload == {"id": "1", "selected": True, "volume": 55, "token": 3.5}

    def test_enqueue_set_omits_volume_when_none(self):
        enqueue_set(_target(), "1", selected=False, volume=None, token=1.0)
        _, _, payload = do._queue.get_nowait()
        assert payload == {"id": "1", "selected": False, "token": 1.0}

    def test_enqueue_set_coerces_selected_and_volume(self):
        enqueue_set(_target(), "1", selected=1, volume="42", token=1.0)
        _, _, payload = do._queue.get_nowait()
        assert payload["selected"] is True
        assert payload["volume"] == 42
        assert isinstance(payload["volume"], int)

    def test_second_fetch_for_same_pending_target_is_dropped(self):
        """A run of queued fetches for the same appliance collapses to
        one — the periodic refresh tick and a post-set refetch must never
        stack up while the first is still sitting in the queue."""
        target = _target(appliance_id="p" * 20)
        enqueue_fetch(target)
        enqueue_fetch(target)
        enqueue_fetch(target)
        assert do._queue.qsize() == 1

    def test_fetch_for_a_different_target_is_not_coalesced(self):
        enqueue_fetch(_target(appliance_id="p" * 20))
        enqueue_fetch(_target(appliance_id="q" * 20))
        assert do._queue.qsize() == 2

    def test_a_new_fetch_can_be_queued_once_the_pending_one_is_dequeued(self):
        target = _target(appliance_id="r" * 20)
        enqueue_fetch(target)
        do._queue.get_nowait()  # simulates the worker picking it up
        with do._pending_fetch_lock:
            do._pending_fetch_ids.discard(target.appliance_id)
        enqueue_fetch(target)
        assert do._queue.qsize() == 1

    def test_enqueue_set_adds_op_pin_and_pin_capable_only_when_given(self):
        target = _target()
        enqueue_set(target, "1", selected=True, volume=None, token=2.0, pin="1234", pin_capable=True)
        assert do._queue.get_nowait()[2] == {
            "id": "1", "selected": True, "token": 2.0, "op": "pin", "pin": "1234", "pin_capable": True}
        enqueue_set(target, "1", selected=True, volume=None, token=2.0, pin_capable=True)
        assert do._queue.get_nowait()[2] == {
            "id": "1", "selected": True, "token": 2.0, "pin_capable": True}
        enqueue_set(target, "1", selected=True, volume=None, token=2.0, pin="1234")
        assert do._queue.get_nowait()[2] == {
            "id": "1", "selected": True, "token": 2.0, "op": "pin", "pin": "1234"}
        enqueue_set(target, "1", selected=True, volume=None, token=2.0)
        assert do._queue.get_nowait()[2] == {"id": "1", "selected": True, "token": 2.0}

    def test_set_is_never_coalesced(self):
        target = _target()
        enqueue_set(target, "1", selected=True, volume=10, token=1.0)
        enqueue_set(target, "1", selected=True, volume=20, token=2.0)
        assert do._queue.qsize() == 2


# ---------------------------------------------------------------------------
# The worker loop: start_outputs_worker, on_result dispatch, fetch-after-set
# ---------------------------------------------------------------------------

class TestWorker:
    def test_worker_sends_fetch_and_calls_on_result(self):
        results = []
        done = threading.Event()

        def on_result(kind, appliance_id, status, body, request):
            results.append((kind, appliance_id, status, body, request))
            done.set()

        patcher, _ = _mock_conn({"ok": True, "outputs": [], "appliance_id": "b" * 20})
        cfg = MagicMock(uuid="dial-uuid")
        with patcher:
            start_outputs_worker(cfg, on_result=on_result)
            enqueue_fetch(_target(appliance_id="b" * 20))
            assert done.wait(timeout=2.0)

        assert len(results) == 1
        kind, appliance_id, status, body, request = results[0]
        assert kind == "fetch"
        assert appliance_id == "b" * 20
        assert status == 200
        assert body["ok"] is True
        assert request == {}

    def test_worker_calls_on_result_for_set_then_enqueues_a_follow_up_fetch(self):
        results = []
        done = threading.Event()

        def on_result(kind, appliance_id, status, body, request):
            results.append(kind)
            if kind == "set":
                done.set()

        patcher, _ = _mock_conn({"ok": True, "id": "1", "appliance_id": "c" * 20})
        cfg = MagicMock(uuid="dial-uuid")
        target = _target(appliance_id="c" * 20)
        with patcher:
            start_outputs_worker(cfg, on_result=on_result)
            enqueue_set(target, "1", selected=True, volume=None, token=1.0)
            assert done.wait(timeout=2.0)
            # The follow-up fetch is enqueued synchronously as part of
            # handling the "set" result, before the worker loops back for
            # its next item — give it a moment to actually be processed too.
            deadline = time.monotonic() + 2.0
            while "fetch" not in results and time.monotonic() < deadline:
                time.sleep(0.01)

        assert results == ["set", "fetch"]

    def test_nothing_the_worker_logs_contains_the_pin(self, caplog):
        seen = []

        def on_result(kind, appliance_id, status, body, request):
            seen.append((kind, request))
            raise RuntimeError("callback boom")

        with patch.object(do, "_queue") as q:
            enqueue_set(
                _target(appliance_id="g" * 20), "1", selected=True, volume=None, token=7.5, pin="4829",
            )
        item = q.put.call_args[0][0]
        patcher, instances = _mock_conn({"ok": False, "pin_invalid": True})
        with caplog.at_level("DEBUG"), patcher:
            saved = do._cfg, do._on_result
            do._cfg, do._on_result = MagicMock(uuid="dial-uuid"), on_result
            try:
                _run_worker_once([item])
            finally:
                do._cfg, do._on_result = saved
        assert "4829" not in caplog.text
        # The appliance is sent the PIN; the callback is told what was asked, without it.
        sent = next(i for i in instances if i.request_called_with["url"].endswith("/set"))
        assert json.loads(sent.request_called_with["body"])["pin"] == "4829"
        set_request = next(r for k, r in seen if k == "set")
        assert "pin" not in set_request and set_request["op"] == "pin"
        assert set_request["token"] == 7.5

    def test_the_token_is_stripped_before_the_wire_and_given_to_the_callback(self):
        seen = []

        def on_result(kind, appliance_id, status, body, request):
            seen.append((kind, request))

        with patch.object(do, "_queue") as q:
            enqueue_set(_target(appliance_id="h" * 20), "1", selected=True, volume=30, token=4.25)
        item = q.put.call_args[0][0]
        patcher, instances = _mock_conn({"ok": True})
        with patcher:
            saved = do._cfg, do._on_result
            do._cfg, do._on_result = MagicMock(uuid="dial-uuid"), on_result
            try:
                _run_worker_once([item])
            finally:
                do._cfg, do._on_result = saved
        sent = next(i for i in instances if i.request_called_with["url"].endswith("/set"))
        wire = json.loads(sent.request_called_with["body"])
        assert "token" not in wire
        assert wire["volume"] == 30
        assert next(r for k, r in seen if k == "set") == {
            "id": "1", "selected": True, "volume": 30, "token": 4.25}

    def test_worker_survives_a_raising_callback_and_keeps_processing(self):
        """A raising on_result for one item must not stop the worker from
        handling the other. Earlier tests in this class leave their own
        (still-idle, daemon) worker threads parked on the shared queue, so
        either of these two items may end up handled by an older thread
        rather than the one this test starts -- the assertion below checks
        both outcomes landed, not which thread or order produced them."""
        calls = []
        calls_lock = threading.Lock()
        both_done = threading.Event()

        def on_result(kind, appliance_id, status, body, request):
            with calls_lock:
                calls.append(appliance_id)
                if len(calls) >= 2:
                    both_done.set()
            if appliance_id == "d" * 20:
                raise RuntimeError("callback boom")

        patcher, _ = _mock_conn({"ok": True, "outputs": []})
        cfg = MagicMock(uuid="dial-uuid")
        with patcher:
            start_outputs_worker(cfg, on_result=on_result)
            enqueue_fetch(_target(appliance_id="d" * 20))
            enqueue_fetch(_target(appliance_id="e" * 20))
            assert both_done.wait(timeout=2.0)

        assert set(calls) == {"d" * 20, "e" * 20}

    def test_worker_runs_with_no_on_result_at_all(self):
        patcher, _ = _mock_conn({"ok": True, "outputs": []})
        cfg = MagicMock(uuid="dial-uuid")
        with patcher:
            start_outputs_worker(cfg, on_result=None)
            enqueue_fetch(_target(appliance_id="f" * 20))
            deadline = time.monotonic() + 2.0
            while not do._queue.empty() and time.monotonic() < deadline:
                time.sleep(0.01)
        assert do._queue.empty()


# ---------------------------------------------------------------------------
# Module isolation: dial_outputs is its own worker, and imports nothing
# from the display/repeat/volume modules.
# ---------------------------------------------------------------------------

class TestModuleIsolation:
    def test_no_dial_display_import(self):
        assert "dial_display" not in do.__dict__
        source = Path(do.__file__).read_text(encoding="utf-8")
        assert "import dial_display" not in source

    def test_no_dial_repeat_or_dial_volume_import(self):
        source = Path(do.__file__).read_text(encoding="utf-8")
        assert "import dial_repeat" not in source
        assert "import dial_volume" not in source

    def test_never_uses_urllib(self):
        source = Path(do.__file__).read_text(encoding="utf-8")
        assert "urllib" not in source
