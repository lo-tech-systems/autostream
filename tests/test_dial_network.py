"""Tests for dial_network.py — the Wi-Fi link poller and the reboot
request. Every network call is faked (http.client.HTTPConnection, the token
file, dial_info.wifi_status), so this suite runs anywhere."""
from __future__ import annotations

import sys
import threading
from pathlib import Path
from unittest.mock import MagicMock, mock_open, patch

import pytest

REPO_ROOT = Path(__file__).parent.parent
_DIAL = str(REPO_ROOT / "dial")
if _DIAL not in sys.path:
    sys.path.insert(0, _DIAL)

import dial_network as dn  # noqa: E402
from dial_info import SIGNAL_NORMAL, SIGNAL_STRONG, SIGNAL_WEAK  # noqa: E402


class _FakeConn:
    """Stands in for http.client.HTTPConnection: records the request, serves
    one canned response."""

    last: "_FakeConn | None" = None

    def __init__(self, host, port, timeout=None, *, status=200, body=b"", raise_on_request=None):
        self.host, self.port, self.timeout = host, port, timeout
        self._status, self._body, self._raise = status, body, raise_on_request
        self.requests: list = []
        self.closed = False
        _FakeConn.last = self

    def request(self, method, path, body=None, headers=None):
        if self._raise is not None:
            raise self._raise
        self.requests.append((method, path, body, dict(headers or {})))

    def getresponse(self):
        resp = MagicMock()
        resp.status = self._status
        resp.read.return_value = self._body
        return resp

    def close(self):
        self.closed = True


def _conn_factory(**kwargs):
    return lambda host, port, timeout=None: _FakeConn(host, port, timeout, **kwargs)


def _snapshot(state: str) -> bytes:
    return ('{"ok": true, "device": {"state": "%s"}}' % state).encode()


@pytest.fixture(autouse=True)
def _reset_module_state():
    dn._latest = dn.UNKNOWN_VIEW
    dn._last_reboot_monotonic = None
    dn._shutdown_pending = False
    yield
    dn._latest = dn.UNKNOWN_VIEW
    dn._last_reboot_monotonic = None
    dn._shutdown_pending = False


class TestClassify:
    @pytest.mark.parametrize("state,link", [
        ("online", dn.LINK_CONNECTED), ("degraded", dn.LINK_CONNECTED),
        ("offline", dn.LINK_DOWN), ("recovering", dn.LINK_DOWN),
        ("setup_mode", dn.LINK_IGNORED), ("reboot_pending", dn.LINK_IGNORED),
        ("unknown", dn.LINK_UNKNOWN), ("", dn.LINK_UNKNOWN), (None, dn.LINK_UNKNOWN), (3, dn.LINK_UNKNOWN),
    ])
    def test_device_state_to_link(self, state, link):
        assert dn.classify_device_state(state) == link

    @pytest.mark.parametrize("category,bars", [
        (SIGNAL_WEAK, 1), (SIGNAL_NORMAL, 2), (SIGNAL_STRONG, 3), ("-", 0), ("", 0), ("Nope", 0),
    ])
    def test_bars(self, category, bars):
        assert dn.bars_for_category(category) == bars


class TestPollOnce:
    def _poll(self, *, token="tok", wifi=("HomeNet", SIGNAL_STRONG), **conn_kwargs):
        token_cm = patch("builtins.open", mock_open(read_data=token + "\n")) if token is not None \
            else patch("builtins.open", side_effect=OSError("no token"))
        with token_cm, patch("dial_network.http.client.HTTPConnection", _conn_factory(**conn_kwargs)), \
             patch("dial_network.wifi_status", return_value=wifi):
            return dn.poll_once(now=100.0)

    def test_connected_view_carries_bars_ssid_and_signal(self):
        view = self._poll(body=_snapshot("online"))
        assert view == dn.NetworkView(link=dn.LINK_CONNECTED, device_state="online", bars=3,
                                      ssid="HomeNet", signal=SIGNAL_STRONG, updated_at=100.0)
        assert dn.latest() is view
        method, path, _, headers = _FakeConn.last.requests[0]
        assert (method, path) == ("GET", "/network_status")
        assert headers["X-Autostream-Wifi-Control"] == "tok"
        assert (_FakeConn.last.host, _FakeConn.last.port) == ("127.0.0.1", 9080)
        assert _FakeConn.last.closed

    def test_degraded_is_connected(self):
        assert self._poll(body=_snapshot("degraded"), wifi=("Net", SIGNAL_WEAK)).bars == 1

    def test_down_view_skips_the_signal_probe(self):
        with patch("dial_network.wifi_status") as ws:
            with patch("builtins.open", mock_open(read_data="tok")), \
                 patch("dial_network.http.client.HTTPConnection", _conn_factory(body=_snapshot("offline"))):
                view = dn.poll_once(now=1.0)
        ws.assert_not_called()
        assert (view.link, view.bars, view.ssid, view.signal) == (dn.LINK_DOWN, 0, "", "")

    def test_recovering_is_down(self):
        assert self._poll(body=_snapshot("recovering")).link == dn.LINK_DOWN

    @pytest.mark.parametrize("state", ["setup_mode", "reboot_pending"])
    def test_ignored_states(self, state):
        assert self._poll(body=_snapshot(state)).link == dn.LINK_IGNORED

    def test_pre_publish_placeholder_is_unknown(self):
        body = b'{"ok": true, "schema_version": 1, "device": {"state": "unknown"}, "stale": true}'
        assert self._poll(body=body).link == dn.LINK_UNKNOWN

    def test_missing_token_is_unknown_and_makes_no_request(self):
        _FakeConn.last = None
        view = self._poll(token=None, body=_snapshot("offline"))
        assert view.link == dn.LINK_UNKNOWN
        assert _FakeConn.last is None

    @pytest.mark.parametrize("kwargs", [
        dict(status=403, body=b'{"ok": false, "error": "forbidden"}'),
        dict(status=200, body=b"not json"),
        dict(status=200, body=b"[1, 2]"),
        dict(status=200, body=b'{"ok": false}'),
        dict(raise_on_request=ConnectionRefusedError()),
        dict(raise_on_request=TimeoutError()),
    ])
    def test_every_failure_is_unknown_not_down(self, kwargs):
        view = self._poll(**kwargs)
        assert view.link == dn.LINK_UNKNOWN and view.bars == 0

    def test_signal_probe_raising_still_yields_connected(self):
        with patch("builtins.open", mock_open(read_data="tok")), \
             patch("dial_network.http.client.HTTPConnection", _conn_factory(body=_snapshot("online"))), \
             patch("dial_network.wifi_status", side_effect=RuntimeError("boom")):
            view = dn.poll_once(now=1.0)
        assert (view.link, view.bars, view.ssid) == (dn.LINK_CONNECTED, 0, "")

    def test_blank_probe_ssid_is_empty_string(self):
        view = self._poll(body=_snapshot("online"), wifi=("-", "-"))
        assert (view.ssid, view.signal, view.bars) == ("", "", 0)


class TestWorker:
    def test_worker_calls_on_view_and_survives_a_raising_callback(self):
        views: list = []
        calls = {"n": 0}

        def on_view(view):
            calls["n"] += 1
            if calls["n"] == 1:
                raise RuntimeError("boom")
            views.append(view)
            dn.stop_network_worker()

        with patch("dial_network.poll_once", return_value=dn.UNKNOWN_VIEW), \
             patch("dial_network.NETWORK_POLL_INTERVAL_S", 0.01):
            dn.start_network_worker(on_view=on_view)
            deadline = threading.Event()
            for _ in range(200):
                if views:
                    break
                deadline.wait(0.01)
        assert views == [dn.UNKNOWN_VIEW]
        assert calls["n"] == 2

    def test_on_tick_called_after_on_view_with_a_monotonic_float(self):
        order: list = []

        def on_view(view):
            order.append(("view", view))

        def on_tick(now):
            order.append(("tick", now))
            dn.stop_network_worker()

        with patch("dial_network.poll_once", return_value=dn.UNKNOWN_VIEW), \
             patch("dial_network.NETWORK_POLL_INTERVAL_S", 0.01):
            dn.start_network_worker(on_view=on_view, on_tick=on_tick)
            deadline = threading.Event()
            for _ in range(200):
                if order:
                    break
                deadline.wait(0.01)
        assert [kind for kind, _ in order] == ["view", "tick"]
        assert isinstance(order[1][1], float)

    def test_raising_on_tick_does_not_kill_the_loop(self):
        calls = {"n": 0}

        def on_tick(now):
            calls["n"] += 1
            if calls["n"] == 1:
                raise RuntimeError("boom")
            dn.stop_network_worker()

        with patch("dial_network.poll_once", return_value=dn.UNKNOWN_VIEW), \
             patch("dial_network.NETWORK_POLL_INTERVAL_S", 0.01):
            dn.start_network_worker(on_tick=on_tick)
            deadline = threading.Event()
            for _ in range(200):
                if calls["n"] >= 2:
                    break
                deadline.wait(0.01)
        assert calls["n"] == 2


class TestRequestShutdown:
    def test_runs_the_helpers_poweroff_verb_through_sudo(self):
        with patch("dial_network.subprocess.run", return_value=MagicMock(returncode=0)) as run,              patch("dial_network.threading.Thread") as thread_cls:
            assert dn.request_shutdown() is True
            _, kwargs = thread_cls.call_args
            assert kwargs["daemon"] is True
            kwargs["target"]()          # run the thread body inline
        assert run.call_args[0][0] == [
            "sudo", "-n", "/usr/local/libexec/autostream/autostream_admin", "poweroff"]

    def test_a_second_request_is_refused_while_one_stands(self):
        with patch("dial_network.threading.Thread") as thread_cls:
            assert dn.request_shutdown() is True
            assert dn.request_shutdown() is False
        assert thread_cls.return_value.start.call_count == 1

    @pytest.mark.parametrize("outcome", [
        MagicMock(returncode=1), RuntimeError("no sudo"),
    ])
    def test_a_request_that_failed_frees_the_slot(self, outcome):
        run = patch("dial_network.subprocess.run", side_effect=None if isinstance(
            outcome, MagicMock) else outcome, return_value=outcome)
        with run, patch("dial_network.threading.Thread") as thread_cls:
            assert dn.request_shutdown() is True
            thread_cls.call_args[1]["target"]()
            assert dn.request_shutdown() is True

    def test_a_request_that_went_through_keeps_the_slot(self):
        with patch("dial_network.subprocess.run", return_value=MagicMock(returncode=0)),              patch("dial_network.threading.Thread") as thread_cls:
            assert dn.request_shutdown() is True
            thread_cls.call_args[1]["target"]()
            assert dn.request_shutdown() is False

    def test_thread_start_failure_is_swallowed_and_frees_the_slot(self):
        with patch("dial_network.threading.Thread", side_effect=RuntimeError("no threads")):
            assert dn.request_shutdown() is False
        with patch("dial_network.threading.Thread"):
            assert dn.request_shutdown() is True


class TestRequestReboot:
    def test_posts_with_the_same_origin_header(self):
        with patch("dial_network.http.client.HTTPConnection", _conn_factory(status=302)), \
             patch("dial_network.threading.Thread") as thread_cls:
            assert dn.request_reboot(now=10.0) is True
            _, kwargs = thread_cls.call_args
            assert kwargs["daemon"] is True
            kwargs["target"]()          # run the thread body inline
        method, path, body, headers = _FakeConn.last.requests[0]
        assert (method, path, body) == ("POST", "/offline/reboot", b"")
        assert headers["X-Requested-With"] == "XMLHttpRequest"
        assert "Origin" not in headers
        assert (_FakeConn.last.host, _FakeConn.last.port) == ("127.0.0.1", 80)

    def test_cooldown_refuses_a_second_request(self):
        with patch("dial_network.threading.Thread") as thread_cls:
            assert dn.request_reboot(now=10.0) is True
            assert dn.request_reboot(now=10.0 + dn.REBOOT_COOLDOWN_S - 1) is False
            assert dn.request_reboot(now=10.0 + dn.REBOOT_COOLDOWN_S) is True
        assert thread_cls.return_value.start.call_count == 2

    def test_transport_failure_never_raises(self):
        with patch("dial_network.http.client.HTTPConnection",
                   _conn_factory(raise_on_request=ConnectionRefusedError())):
            assert dn._post_reboot() is None
            dn._reboot_thread()      # logs a warning, returns

    def test_thread_start_failure_is_swallowed(self):
        with patch("dial_network.threading.Thread", side_effect=RuntimeError("no threads")):
            assert dn.request_reboot(now=50.0) is False
