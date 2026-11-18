"""Tests for autostream_peer_http: JSON requests, event streams and their parser."""
from __future__ import annotations

import io
import socket
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "core"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import autostream_peer_http as http_mod  # noqa: E402
from fake_peer_server import FakePeer  # noqa: E402


def sse(text: str, **kw):
    return list(http_mod.read_events(io.BytesIO(text.encode()), **kw))


class TestReadEvents:
    def test_event_with_id_name_and_data(self):
        events = sse("id: a-1\nevent: change\ndata: {\"x\":1}\n\n")
        assert events == [http_mod.SseEvent("a-1", "change", '{"x":1}')]

    def test_multi_line_data_is_joined(self):
        events = sse("data: one\ndata: two\n\n")
        assert events == [http_mod.SseEvent(None, "message", "one\ntwo")]

    def test_comment_and_retry_lines_are_keepalives(self):
        events = sse(": ka\n\nretry: 2000\n\n")
        assert [e.event for e in events] == ["ka", "ka"]

    def test_block_without_data_yields_nothing(self):
        assert sse("event: change\n\n") == []

    def test_crlf_and_field_without_space(self):
        events = sse("event:access\r\ndata:{}\r\n\r\n")
        assert events == [http_mod.SseEvent(None, "access", "{}")]

    def test_stream_ending_mid_block_drops_the_block(self):
        assert sse("data: partial") == []

    def test_a_line_over_the_cap_is_bad_reply(self):
        with pytest.raises(http_mod.StreamError) as info:
            sse("data: " + "x" * 200 + "\n\n", line_cap=64)
        assert info.value.name == "bad_reply"


class _Odd(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        if self.path == "/big":
            body = b'{"pad":"' + b"x" * 5000 + b'"}'
        elif self.path == "/list":
            body = b"[1,2]"
        elif self.path == "/slow":
            threading.Event().wait(1.0)
            body = b"{}"
        else:
            body = b"<html>nope</html>"
        self.send_response(502 if self.path == "/html" else 200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        data = self.rfile.read(n)
        self.server.seen = (self.path, dict(self.headers), data)
        body = b'{"ok":true}'
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture
def odd():
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Odd)
    httpd.daemon_threads = True
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield httpd
    httpd.shutdown()
    httpd.server_close()


class TestRequestJson:
    def test_reads_an_object(self):
        peer = FakePeer().start()
        try:
            status, body, err = http_mod.request_json("127.0.0.1", peer.port, "GET", "/api/v1/state")
        finally:
            peer.stop()
        assert (status, err) == (200, "")
        assert body["boot"] == peer.boot

    def test_post_sends_json_and_host(self, odd):
        port = odd.server_address[1]
        status, body, err = http_mod.request_json(
            "127.0.0.1", port, "POST", "/x", body={"a": 1})
        path, headers, data = odd.seen
        assert (status, body, err) == (200, {"ok": True}, "")
        assert data == b'{"a":1}'
        assert headers["Host"] == f"127.0.0.1:{port}"
        assert headers["Content-Type"] == "application/json"
        assert "Origin" not in headers

    def test_refused_connection_is_unreachable(self):
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        assert http_mod.request_json("127.0.0.1", port, "GET", "/") == (0, None, "unreachable")

    def test_slow_reply_is_timeout(self, odd):
        status, body, err = http_mod.request_json(
            "127.0.0.1", odd.server_address[1], "GET", "/slow", read_s=0.2)
        assert (status, body, err) == (0, None, "timeout")

    def test_closed_before_reply_is_unreachable(self):
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        threading.Thread(target=lambda: srv.accept()[0].close(), daemon=True).start()
        try:
            out = http_mod.request_json("127.0.0.1", srv.getsockname()[1], "GET", "/")
        finally:
            srv.close()
        assert out == (0, None, "unreachable")

    def test_html_body_is_bad_reply_with_its_status(self, odd):
        out = http_mod.request_json("127.0.0.1", odd.server_address[1], "GET", "/html")
        assert out == (502, None, "bad_reply")

    def test_a_list_is_bad_reply(self, odd):
        out = http_mod.request_json("127.0.0.1", odd.server_address[1], "GET", "/list")
        assert out == (200, None, "bad_reply")

    def test_body_over_the_cap_is_bad_reply(self, odd):
        out = http_mod.request_json("127.0.0.1", odd.server_address[1], "GET", "/big", cap=1000)
        assert out == (200, None, "bad_reply")

    def test_tracker_sees_the_socket_and_then_none(self):
        peer = FakePeer().start()
        seen = []
        try:
            http_mod.request_json("127.0.0.1", peer.port, "GET", "/api/v1/state",
                                  track=lambda s: seen.append(s is not None))
        finally:
            peer.stop()
        assert seen == [True, False]


class TestOpenEvents:
    def test_open_stream(self):
        peer = FakePeer().start()
        try:
            resp, status, refusal, err = http_mod.open_events(
                "127.0.0.1", peer.port, "/api/v1/events?client=peer:" + "0" * 20)
            assert (status, refusal, err) == (200, None, "")
            first = next(http_mod.read_events(resp))
            assert first.event == "ka"          # the retry line
            resp.close()
        finally:
            peer.stop()

    def test_refusal_body(self):
        peer = FakePeer().start()
        peer.refusal = (503, {"ok": False, "error": "too_many_clients"})
        try:
            resp, status, refusal, err = http_mod.open_events("127.0.0.1", peer.port, "/api/v1/events")
        finally:
            peer.stop()
        assert resp is None and status == 503 and refusal["error"] == "too_many_clients" and err == ""

    def test_protocol_mismatch_body(self):
        peer = FakePeer(protocol=99).start()
        try:
            resp, status, refusal, err = http_mod.open_events("127.0.0.1", peer.port, "/api/v1/events")
        finally:
            peer.stop()
        assert resp is None and refusal["error"] == "protocol_mismatch"

    def test_last_event_id_header(self):
        peer = FakePeer().start()
        try:
            resp, *_ = http_mod.open_events("127.0.0.1", peer.port, "/api/v1/events",
                                            last_event_id="abc-1")
            resp.close()
        finally:
            peer.stop()
        assert peer.connects[0]["last_event_id"] == "abc-1"

    def test_unreachable(self):
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        assert http_mod.open_events("127.0.0.1", port, "/") == (None, 0, None, "unreachable")
