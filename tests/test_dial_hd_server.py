"""Tests for the HD dial's loopback server: a real HdServer on an ephemeral
127.0.0.1 port, driven with http.client and raw sockets against a FakeCore."""
from __future__ import annotations

import http.client
import json
import os
import socket
import sys
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "dial"))

import dial_hd_server as hds
import hd_scenarios as hs
from hd_fake_core import FakeCore
from dial_config import DialDisplayConfig
from dial_core_state import Artwork, artwork_key
from dial_hd_backdrop import BackdropStore
from dial_hd_state import build_state

PAGE = b"<!doctype html><title>t</title>"
CSS = b"body{}"
JS = b"(function(){})();"
THEME = b":root{}"
JPEG = b"\xff\xd8\xff\xe0" + b"\x00" * 16
GIF = b"GIF89a" + b"\x00" * 16
WEBP = b"RIFF\x00\x00\x00\x00WEBPVP8 "


class _Http:
    """What the server reads from the management server."""

    def __init__(self):
        self.display_config = DialDisplayConfig(brightness=60, sleep_after_s=900)
        self.status = {"recovery_active": True, "volume_confirmed": False}

    def get_runtime_status(self):
        return dict(self.status)


@pytest.fixture
def static_root(tmp_path):
    root = tmp_path / "hd"
    root.mkdir()
    (root / "index.html").write_bytes(PAGE)
    (root / "hd.css").write_bytes(CSS)
    (root / "hd.js").write_bytes(JS)
    (root / "theme.css").write_bytes(THEME)
    return root


@pytest.fixture
def core():
    return FakeCore(hs.SCENARIOS["playing_artwork"].snapshot)


@pytest.fixture
def make_server(core, static_root):
    servers = []

    def make(**kwargs):
        kwargs.setdefault("http_server", _Http())
        kwargs.setdefault("static_root", static_root)
        kwargs.setdefault("muted_fn", lambda service: True)
        kwargs.setdefault("port", 0)
        server = hds.HdServer(SimpleNamespace(), core, **kwargs)
        server.start()
        servers.append(server)
        return server

    yield make
    for server in servers:
        server.stop()


@pytest.fixture
def server(make_server):
    return make_server()


def request(server, method, path, body=None, headers=None, host=None):
    conn = http.client.HTTPConnection("127.0.0.1", server.port, timeout=5)
    sent = dict(headers or {})
    if host is not None:
        conn.putrequest(method, path, skip_host=True)
        conn.putheader("Host", host)
        for name, value in sent.items():
            conn.putheader(name, value)
        if body is not None:
            conn.putheader("Content-Length", str(len(body)))
        conn.endheaders(body)
    else:
        conn.request(method, path, body=body, headers=sent)
    response = conn.getresponse()
    data = response.read()
    conn.close()
    return response, data


def raw(server, payload: bytes, timeout=5) -> bytes:
    with socket.create_connection(("127.0.0.1", server.port), timeout=timeout) as sock:
        sock.sendall(payload)
        chunks = []
        while True:
            try:
                chunk = sock.recv(65536)
            except socket.timeout:
                break
            if not chunk:
                break
            chunks.append(chunk)
    return b"".join(chunks)


def error_of(data: bytes) -> str:
    return json.loads(data)["error"]


POST_HEADERS = {"X-Requested-With": "autostream-hd", "Content-Type": "application/json"}


def _echo_route(handler, rest):
    body = handler.read_json_body()
    if body is not None:
        handler.send_json(200, {"ok": True, "echo": body})


def _boom_route(handler, rest):
    raise RuntimeError("secret appliance text")


@pytest.fixture
def post_server(make_server):
    return make_server(extra_routes=(
        ("POST", "/api/v1/echo", _echo_route),
        ("GET", "/api/v1/boom", _boom_route),
    ))


# ---- the listener ---------------------------------------------------------


class TestListener:
    def test_the_default_port_is_7843_and_the_listener_is_loopback_only(self, server):
        assert hds.HD_PORT == 7843
        assert server._server.server_address[0] == "127.0.0.1"

    def test_the_configured_port_is_bound(self, make_server):
        free = socket.socket()
        free.bind(("127.0.0.1", 0))
        port = free.getsockname()[1]
        free.close()
        assert make_server(port=port).port == port

    def test_stop_closes_the_listener(self, make_server):
        server = make_server()
        port = server.port
        server.stop()
        with pytest.raises(OSError):
            socket.create_connection(("127.0.0.1", port), timeout=1)

    def test_stop_before_start_does_not_hang(self, core, static_root):
        server = hds.HdServer(SimpleNamespace(), core, static_root=static_root, port=0)
        server.stop()


# ---- the page and static files ---------------------------------------------


class TestStaticFiles:
    def test_the_index_is_served_at_the_root_with_the_page_headers(self, server):
        response, data = request(server, "GET", "/")
        assert response.status == 200
        assert data == PAGE
        assert response.getheader("Content-Type") == "text/html; charset=utf-8"
        assert response.getheader("Content-Security-Policy") == (
            "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'")
        assert response.getheader("X-Content-Type-Options") == "nosniff"
        assert response.getheader("Referrer-Policy") == "no-referrer"
        assert response.getheader("X-Frame-Options") == "DENY"
        assert response.getheader("Cache-Control") == "no-cache"
        assert response.getheader("ETag")

    @pytest.mark.parametrize("name, body, content_type", [
        ("hd.css", CSS, "text/css; charset=utf-8"),
        ("hd.js", JS, "text/javascript; charset=utf-8"),
        ("theme.css", THEME, "text/css; charset=utf-8"),
    ])
    def test_static_files_carry_their_type_and_the_page_headers(self, server, name, body, content_type):
        response, data = request(server, "GET", "/static/" + name)
        assert (response.status, data) == (200, body)
        assert response.getheader("Content-Type") == content_type
        assert response.getheader("X-Content-Type-Options") == "nosniff"
        assert "script-src 'self'" in response.getheader("Content-Security-Policy")

    def test_a_matching_etag_is_a_304_and_a_changed_file_is_a_200(self, server, static_root):
        etag = request(server, "GET", "/static/hd.js")[0].getheader("ETag")
        response, data = request(server, "GET", "/static/hd.js", headers={"If-None-Match": etag})
        assert (response.status, data) == (304, b"")
        assert response.getheader("ETag") == etag
        (static_root / "hd.js").write_bytes(JS + b"//changed")
        response, data = request(server, "GET", "/static/hd.js", headers={"If-None-Match": etag})
        assert response.status == 200
        assert data.endswith(b"//changed")
        assert response.getheader("ETag") != etag

    def test_theme_falls_back_to_the_repository_copy(self, make_server, static_root):
        (static_root / "theme.css").unlink()
        response, data = request(make_server(), "GET", "/static/theme.css")
        assert response.status == 200
        assert data == (hs.REPO_ROOT / "nginx" / "static" / "theme.css").read_bytes()

    def test_the_logo_is_served_as_a_png(self, server):
        response, data = request(server, "GET", "/static/logo.png")
        assert response.status == 200
        assert response.getheader("Content-Type") == "image/png"
        assert data.startswith(b"\x89PNG")

    @pytest.mark.parametrize("path", [
        "/static/", "/static/nothing.js", "/static/../dial_hd_server.py", "/static/%2e%2e/x",
        "/static/hd.js/", "/static/index.html",
    ])
    def test_names_outside_the_fixed_table_are_not_found(self, server, path):
        response, data = request(server, "GET", path)
        assert response.status == 404
        assert error_of(data) == "not_found"

    def test_a_missing_file_is_not_found(self, server, static_root):
        (static_root / "hd.css").unlink()
        assert request(server, "GET", "/static/hd.css")[0].status == 404

    def test_a_query_string_does_not_change_the_route(self, server):
        assert request(server, "GET", "/?x=1")[1] == PAGE

    def test_the_shipped_page_files_exist_and_the_index_loads_only_static_files(self):
        root = hds.HD_STATIC_ROOT
        index = (root / "index.html").read_text(encoding="utf-8")
        for name in ("hd.css", "hd.js"):
            assert (root / name).is_file()
            assert f"/static/{name}" in index


# ---- request checks --------------------------------------------------------


class TestRequestChecks:
    @pytest.mark.parametrize("host", ["127.0.0.1", "localhost", "LOCALHOST", None])
    def test_loopback_hosts_are_accepted(self, server, host):
        host = f"{host}:{server.port}" if host else None
        assert request(server, "GET", "/api/v1/state", host=host)[0].status == 200

    def test_a_host_without_a_port_is_accepted(self, server):
        assert request(server, "GET", "/", host="127.0.0.1")[0].status == 200

    @pytest.mark.parametrize("host", [
        "evil.example", "evil.example:{port}", "127.0.0.1.evil.example:{port}", "192.0.2.10:{port}",
        "127.0.0.1:1", "localhost:", "[::1]:{port}", "0.0.0.0:{port}", "",
    ])
    def test_other_hosts_are_refused(self, server, host):
        response, data = request(server, "GET", "/api/v1/state", host=host.format(port=server.port))
        assert response.status == 403
        assert error_of(data) == "bad_host"

    def test_a_request_with_no_host_is_refused(self, server):
        reply = raw(server, b"GET /api/v1/state HTTP/1.0\r\n\r\n")
        assert reply.startswith(b"HTTP/1.1 403")

    def test_an_origin_that_does_not_match_the_host_is_refused(self, server):
        response, data = request(server, "GET", "/api/v1/state", headers={"Origin": "http://evil.example"})
        assert response.status == 403
        assert error_of(data) == "bad_origin"

    def test_a_matching_origin_is_accepted(self, server):
        origin = f"http://127.0.0.1:{server.port}"
        assert request(server, "GET", "/api/v1/state", headers={"Origin": origin})[0].status == 200

    def test_no_response_ever_carries_cors_headers(self, post_server):
        origin = f"http://127.0.0.1:{post_server.port}"
        for method, path, headers in (
            ("GET", "/", {"Origin": origin}),
            ("GET", "/api/v1/state", {"Origin": origin}),
            ("GET", "/api/v1/state", {"Origin": "http://evil.example"}),
            ("OPTIONS", "/api/v1/echo", {"Origin": "http://evil.example",
                                         "Access-Control-Request-Method": "POST"}),
            ("POST", "/api/v1/echo", {"Origin": origin}),
            ("GET", "/api/v1/nothing", {}),
        ):
            response, _ = request(post_server, method, path, headers=headers)
            names = [name.lower() for name, _ in response.getheaders()]
            assert not [n for n in names if n.startswith("access-control-")], (method, path)

    def test_an_options_preflight_is_not_answered(self, post_server):
        response, _ = request(post_server, "OPTIONS", "/api/v1/echo", headers={"Origin": "http://x"})
        assert response.status == 403 or response.status == 405
        assert response.getheader("Access-Control-Allow-Origin") is None

    def test_an_overlong_request_line_is_refused(self, server):
        reply = raw(server, b"GET /" + b"a" * 2000 + b" HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
        assert reply.startswith(b"HTTP/1.1 414")

    def test_unsupported_methods_are_405_with_allow(self, server):
        response, data = request(server, "PUT", "/api/v1/state")
        assert response.status == 405
        assert response.getheader("Allow") == "GET"
        assert error_of(data) == "method_not_allowed"
        assert request(server, "DELETE", "/")[0].status == 405

    def test_an_unknown_route_is_404(self, server):
        response, data = request(server, "GET", "/api/v1/nothing")
        assert (response.status, error_of(data)) == (404, "not_found")
        assert request(server, "POST", "/nothing", headers=POST_HEADERS)[0].status == 404

    def test_a_malformed_request_line_is_an_error_not_a_hang(self, server):
        reply = raw(server, b"NONSENSE\r\n\r\n")
        assert b"bad_request" in reply or reply == b""


class TestPostHardening:
    def test_a_post_without_the_custom_header_is_refused(self, post_server):
        response, data = request(post_server, "POST", "/api/v1/echo", body=b"{}")
        assert response.status == 403
        assert error_of(data) == "missing_request_header"

    def test_a_post_with_the_wrong_header_value_is_refused(self, post_server):
        response, _ = request(post_server, "POST", "/api/v1/echo", body=b"{}",
                              headers={"X-Requested-With": "XMLHttpRequest"})
        assert response.status == 403

    def test_a_post_with_the_header_reaches_the_handler(self, post_server):
        response, data = request(post_server, "POST", "/api/v1/echo", body=b'{"a": 1}', headers=POST_HEADERS)
        assert response.status == 200
        assert json.loads(data) == {"ok": True, "echo": {"a": 1}}

    def test_an_empty_body_is_an_empty_object(self, post_server):
        response, data = request(post_server, "POST", "/api/v1/echo", headers=POST_HEADERS)
        assert json.loads(data)["echo"] == {}

    def test_a_body_over_the_cap_is_413_without_being_read(self, post_server):
        response, data = request(post_server, "POST", "/api/v1/echo",
                                 body=b"x" * (hds.MAX_BODY + 1), headers=POST_HEADERS)
        assert response.status == 413
        assert error_of(data) == "body_too_large"

    def test_a_body_at_the_cap_is_accepted(self, post_server):
        pad = "x" * (hds.MAX_BODY - len('{"p": ""}'))
        body = json.dumps({"p": pad}).encode()
        assert len(body) == hds.MAX_BODY
        assert request(post_server, "POST", "/api/v1/echo", body=body, headers=POST_HEADERS)[0].status == 200

    @pytest.mark.parametrize("body", [b"[1]", b'"x"', b"3", b"null", b"true"])
    def test_a_body_that_is_not_an_object_is_refused(self, post_server, body):
        response, data = request(post_server, "POST", "/api/v1/echo", body=body, headers=POST_HEADERS)
        assert (response.status, error_of(data)) == (400, "body_must_be_object")

    @pytest.mark.parametrize("body", [b"{", b"\xff\xfe", b"not json"])
    def test_a_body_that_is_not_json_is_refused(self, post_server, body):
        response, data = request(post_server, "POST", "/api/v1/echo", body=body, headers=POST_HEADERS)
        assert (response.status, error_of(data)) == (400, "bad_json")

    def test_a_bad_content_length_is_refused(self, post_server):
        reply = raw(post_server, (
            f"POST /api/v1/echo HTTP/1.1\r\nHost: 127.0.0.1:{post_server.port}\r\n"
            "X-Requested-With: autostream-hd\r\nContent-Length: abc\r\n\r\n").encode())
        assert reply.startswith(b"HTTP/1.1 400")

    def test_a_chunked_body_is_refused(self, post_server):
        reply = raw(post_server, (
            f"POST /api/v1/echo HTTP/1.1\r\nHost: 127.0.0.1:{post_server.port}\r\n"
            "X-Requested-With: autostream-hd\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n").encode())
        assert reply.startswith(b"HTTP/1.1 411")

    def test_a_get_on_a_post_route_is_405(self, post_server):
        response, _ = request(post_server, "GET", "/api/v1/echo")
        assert response.status == 405
        assert response.getheader("Allow") == "POST"


class TestFailures:
    def test_a_handler_that_raises_answers_500_and_the_server_survives(self, post_server):
        response, data = request(post_server, "GET", "/api/v1/boom")
        assert (response.status, error_of(data)) == (500, "internal_error")
        assert b"secret" not in data
        assert request(post_server, "GET", "/api/v1/state")[0].status == 200

    def test_a_client_that_hangs_up_mid_request_changes_nothing(self, server):
        with socket.create_connection(("127.0.0.1", server.port), timeout=2) as sock:
            sock.sendall(b"GET /api/v1/sta")
        assert request(server, "GET", "/api/v1/state")[0].status == 200

    def test_a_client_that_never_finishes_its_request_is_dropped_and_blocks_no_one(
            self, monkeypatch, make_server):
        monkeypatch.setattr(hds, "CLIENT_WRITE_TIMEOUT_S", 0.3)
        server = make_server()
        stalled = socket.create_connection(("127.0.0.1", server.port), timeout=5)
        try:
            stalled.sendall(b"GET /api/v1/state HTTP/1.1\r\nHost: 127.0.0.1")
            started = time.monotonic()
            assert request(server, "GET", "/api/v1/state")[0].status == 200
            assert time.monotonic() - started < 0.25
            stalled.settimeout(3)
            assert stalled.recv(1024) == b""        # closed by the server's timeout
        finally:
            stalled.close()

    def test_many_stalled_connections_do_not_stop_requests(self, server):
        sockets = [socket.create_connection(("127.0.0.1", server.port)) for _ in range(20)]
        try:
            assert request(server, "GET", "/api/v1/state")[0].status == 200
        finally:
            for sock in sockets:
                sock.close()


# ---- the state route -------------------------------------------------------


class TestState:
    def test_the_state_body_is_the_serialised_snapshot(self, server, core):
        response, data = request(server, "GET", "/api/v1/state")
        assert response.status == 200
        assert response.getheader("Content-Type") == "application/json"
        assert response.getheader("Cache-Control") == "no-store"
        assert response.getheader("X-Content-Type-Options") == "nosniff"
        body = json.loads(data)
        assert body["v"] == 1
        assert body["core_seq"] == core.snapshot().seq
        assert body["now_playing"]["title"] == "Tunnel of Love"
        assert body["artwork"]["url"] == "/api/v1/artwork/" + core.snapshot().artwork.key

    def test_the_impure_reads_are_folded_in(self, make_server, core):
        http_server = _Http()
        seen = []

        def muted(service):
            seen.append(service)
            return True

        server = make_server(http_server=http_server, muted_fn=muted, panel=SimpleNamespace(
            view=lambda: {"asleep": True, "backlight": "sysfs"}))
        body = json.loads(request(server, "GET", "/api/v1/state")[1])
        assert seen == ["Lounge"]
        assert body["volume"]["muted"] is True
        assert body["panel"]["asleep"] is True
        assert body["panel"]["brightness"] == 60
        assert body["panel"]["sleep_after_s"] == 900
        assert body["recovery"] == {"active": True, "confirmed": False}

    def test_the_body_matches_build_state_for_the_same_inputs(self, make_server, core):
        scenario = hs.SCENARIOS["playing_artwork"]
        server = make_server(
            muted_fn=lambda service: False, clock=lambda: hs.NOW, wall_clock=lambda: hs.WALL_NOW,
            panel=SimpleNamespace(view=lambda: dict(hs.PANEL_AWAKE)),
        )
        server._http_server.display_config = DialDisplayConfig(brightness=80, sleep_after_s=300)
        server._http_server.status = {"recovery_active": False, "volume_confirmed": False}
        body = json.loads(request(server, "GET", "/api/v1/state")[1])
        expected = build_state(
            scenario.snapshot, descriptors=core.warnings.descriptors(), panel=hs.PANEL_AWAKE,
            settings={"brightness": 80, "sleep_after_s": 300, "always_show_controls": False},
            recovery=(False, False), hub_seq=scenario.snapshot.seq, now=hs.NOW,
            wall_now=hs.WALL_NOW, muted=False)
        assert body == json.loads(json.dumps(expected))

    def test_a_newly_published_snapshot_is_served(self, server, core):
        before = json.loads(request(server, "GET", "/api/v1/state")[1])["core_seq"]
        core.publish(polling=False)
        body = json.loads(request(server, "GET", "/api/v1/state")[1])
        assert body["core_seq"] == before + 1
        assert body["polling"] is False

    def test_no_appliance_address_or_service_name_reaches_the_body(self, server):
        data = request(server, "GET", "/api/v1/state")[1].decode()
        assert hs.ARTWORK_URL not in data
        assert hs.SERVICE_NAME not in data

    def test_the_server_works_with_no_management_server(self, make_server):
        server = make_server(http_server=None)
        body = json.loads(request(server, "GET", "/api/v1/state")[1])
        assert body["recovery"] == {"active": False, "confirmed": False}

    def test_every_scenario_serialises_over_the_wire(self, make_server, core):
        server = make_server()
        for name, scenario in hs.SCENARIOS.items():
            core.publish(scenario.snapshot)
            response, data = request(server, "GET", "/api/v1/state")
            assert response.status == 200, name
            assert json.loads(data)["v"] == 1


# ---- artwork ---------------------------------------------------------------


class TestArtwork:
    def key(self, core):
        return core.snapshot().artwork.key

    def test_the_held_artwork_is_served_by_key(self, server, core):
        response, data = request(server, "GET", "/api/v1/artwork/" + self.key(core))
        assert response.status == 200
        assert data == hs.ARTWORK_BYTES
        assert response.getheader("Content-Type") == "image/png"
        assert response.getheader("Content-Length") == str(len(hs.ARTWORK_BYTES))
        assert response.getheader("Cache-Control") == "private, max-age=86400, immutable"
        assert response.getheader("X-Content-Type-Options") == "nosniff"
        assert response.getheader("ETag") == '"%s"' % self.key(core)

    def test_a_matching_etag_is_a_304(self, server, core):
        key = self.key(core)
        response, data = request(server, "GET", "/api/v1/artwork/" + key,
                                 headers={"If-None-Match": '"%s"' % key})
        assert (response.status, data) == (304, b"")
        assert response.getheader("Cache-Control") == "private, max-age=86400, immutable"

    def test_another_etag_is_a_200(self, server, core):
        response, _ = request(server, "GET", "/api/v1/artwork/" + self.key(core),
                              headers={"If-None-Match": '"0123456789abcdef"'})
        assert response.status == 200

    def test_a_key_that_is_not_held_is_404(self, server):
        response, data = request(server, "GET", "/api/v1/artwork/0123456789abcdef")
        assert (response.status, error_of(data)) == (404, "no_artwork")

    def test_no_held_artwork_is_404(self, server, core):
        key = self.key(core)
        core.publish(artwork=None)
        assert request(server, "GET", "/api/v1/artwork/" + key)[0].status == 404

    @pytest.mark.parametrize("key", [
        "", "short", "0123456789ABCDEF", "0123456789abcdeg", "0123456789abcdef0",
        "../state", "0123456789abcde/", "%30123456789abcdef",
    ])
    def test_a_malformed_key_is_400(self, server, key):
        response, data = request(server, "GET", "/api/v1/artwork/" + key)
        assert (response.status, error_of(data)) == (400, "bad_artwork_key")

    @pytest.mark.parametrize("data, content_type", [
        (JPEG, "image/jpeg"), (hs.ARTWORK_BYTES, "image/png"), (GIF, "image/gif"),
        (WEBP, "image/webp"), (b"<html>", "application/octet-stream"), (b"", "application/octet-stream"),
        (b"RIFF\x00\x00\x00\x00WAVE", "application/octet-stream"),
    ])
    def test_the_type_is_sniffed_from_the_bytes(self, server, core, data, content_type):
        key = artwork_key("https://provider.example/other.bin")
        core.publish(artwork=Artwork("", key, data, "text/html", 0.0))
        response, body = request(server, "GET", "/api/v1/artwork/" + key)
        assert response.getheader("Content-Type") == content_type
        assert body == data

    def test_the_bytes_are_written_without_holding_anything_the_core_needs(self, server, core):
        # A large image streams to a slow reader while the core keeps publishing.
        key = artwork_key("https://provider.example/big.jpg")
        big = JPEG + b"\x00" * (2 * 1024 * 1024)
        core.publish(artwork=Artwork("", key, big, "", 0.0))
        sock = socket.create_connection(("127.0.0.1", server.port))
        try:
            sock.sendall(f"GET /api/v1/artwork/{key} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n".encode())
            started = time.monotonic()
            for _ in range(20):
                core.publish(polling=True)
            assert time.monotonic() - started < 0.5
            assert request(server, "GET", "/api/v1/state")[0].status == 200
        finally:
            sock.close()


# ---- backdrops -------------------------------------------------------------

BACKDROP_JPEG = JPEG + b"backdrop"


class _Render:
    def __init__(self, result=BACKDROP_JPEG):
        self.calls = []
        self.result = result

    def __call__(self, arg):
        self.calls.append(arg)
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


class TestBackdrop:
    @pytest.fixture
    def art_render(self):
        return _Render()

    @pytest.fixture
    def logo_render(self):
        return _Render()

    @pytest.fixture
    def bserver(self, make_server, art_render, logo_render):
        store = BackdropStore(hs.REPO_ROOT / "images" / "autostream-logo-centred-dark.png",
                              render_artwork=art_render, render_logo=logo_render)
        return make_server(backdrops=store)

    def key(self, core):
        return core.snapshot().artwork.key

    def path(self, core, suffix="/backdrop"):
        return "/api/v1/artwork/" + self.key(core) + suffix

    def test_the_held_artworks_backdrop_is_served(self, bserver, core, art_render):
        response, data = request(bserver, "GET", self.path(core))
        assert response.status == 200
        assert data == BACKDROP_JPEG
        assert response.getheader("Content-Type") == "image/jpeg"
        assert response.getheader("Content-Length") == str(len(BACKDROP_JPEG))
        assert response.getheader("Cache-Control") == "private, max-age=86400, immutable"
        assert response.getheader("X-Content-Type-Options") == "nosniff"
        assert response.getheader("ETag") == '"%s"' % self.key(core)
        assert art_render.calls == [hs.ARTWORK_BYTES]

    def test_a_matching_etag_is_a_304_without_a_render(self, bserver, core, art_render):
        response, data = request(bserver, "GET", self.path(core),
                                 headers={"If-None-Match": '"%s"' % self.key(core)})
        assert (response.status, data) == (304, b"")
        assert art_render.calls == []

    def test_a_second_request_reuses_the_render(self, bserver, core, art_render):
        for _ in range(3):
            assert request(bserver, "GET", self.path(core))[0].status == 200
        assert len(art_render.calls) == 1

    def test_a_released_key_is_404_and_the_entry_is_not_served(self, bserver, core, art_render):
        held = core.snapshot().artwork
        path = self.path(core)
        assert request(bserver, "GET", path)[0].status == 200
        core.publish(artwork=None)
        response, data = request(bserver, "GET", path)
        assert (response.status, error_of(data)) == (404, "no_artwork")
        core.publish(artwork=held)
        assert request(bserver, "GET", path)[0].status == 200
        assert len(art_render.calls) == 1

    def test_a_different_held_key_renders_again_and_replaces_the_first(self, bserver, core, art_render):
        held = core.snapshot().artwork
        first = self.path(core)
        assert request(bserver, "GET", first)[0].status == 200
        other = artwork_key("https://provider.example/other.jpg")
        core.publish(artwork=Artwork("", other, JPEG, "", 0.0))
        assert request(bserver, "GET", "/api/v1/artwork/%s/backdrop" % other)[0].status == 200
        assert len(art_render.calls) == 2
        core.publish(artwork=held)
        assert request(bserver, "GET", first)[0].status == 200
        assert len(art_render.calls) == 3

    def test_an_unrenderable_cover_is_404_once(self, make_server, core):
        render = _Render(None)
        server = make_server(backdrops=BackdropStore(Path("x"), render_artwork=render))
        for _ in range(2):
            response, data = request(server, "GET", self.path(core))
            assert (response.status, error_of(data)) == (404, "no_backdrop")
        assert len(render.calls) == 1

    def test_a_renderer_that_raises_is_404_and_the_server_survives(self, make_server, core):
        render = _Render(RuntimeError("secret decoder text"))
        server = make_server(backdrops=BackdropStore(Path("x"), render_artwork=render))
        response, data = request(server, "GET", self.path(core))
        assert (response.status, error_of(data)) == (404, "no_backdrop")
        assert b"secret" not in data
        assert request(server, "GET", "/api/v1/state")[0].status == 200

    def test_the_plain_artwork_is_untouched_and_never_renders(self, bserver, core, art_render):
        response, data = request(bserver, "GET", self.path(core, ""))
        assert (response.status, data) == (200, hs.ARTWORK_BYTES)
        assert art_render.calls == []

    @pytest.mark.parametrize("suffix", ["/", "/backdrop/", "/Backdrop", "/other", "/backdrop/x"])
    def test_malformed_variants_are_400(self, bserver, core, suffix):
        response, data = request(bserver, "GET", self.path(core, suffix))
        assert (response.status, error_of(data)) == (400, "bad_artwork_key")

    def test_a_backdrop_without_a_key_is_400(self, bserver):
        response, data = request(bserver, "GET", "/api/v1/artwork//backdrop")
        assert (response.status, error_of(data)) == (400, "bad_artwork_key")
        response, data = request(bserver, "GET", "/api/v1/artwork/backdrop")
        assert (response.status, error_of(data)) == (400, "bad_artwork_key")

    def test_the_two_key_patterns_agree(self):
        for rest in ("0123456789abcdef", "0123456789ABCDEF", "short", "", "../state",
                     "0123456789abcdef0", "0123456789abcdeg"):
            assert bool(hds.ARTWORK_KEY_RE.match(rest)) == bool(hds.ARTWORK_REST_RE.match(rest))

    def test_concurrent_requests_cost_one_render_and_block_nothing(self, make_server, core):
        release = threading.Event()
        entered = threading.Event()
        calls = []

        def slow(data):
            calls.append(data)
            entered.set()
            release.wait(5)
            return BACKDROP_JPEG

        server = make_server(backdrops=BackdropStore(Path("x"), render_artwork=slow))
        path = self.path(core)
        results = []
        threads = [threading.Thread(target=lambda: results.append(request(server, "GET", path)))
                   for _ in range(2)]
        threads[0].start()
        assert entered.wait(5)
        threads[1].start()
        try:
            started = time.monotonic()
            assert request(server, "GET", "/api/v1/state")[0].status == 200
            for _ in range(20):
                core.publish(polling=True)
            assert time.monotonic() - started < 0.5
        finally:
            release.set()
            for thread in threads:
                thread.join(5)
        assert [r[0].status for r in results] == [200, 200]
        assert results[0][1] == results[1][1] == BACKDROP_JPEG
        assert len(calls) == 1

    # ---- the logo's backdrop ----

    def test_the_logo_backdrop_is_served_with_the_logos_etag(self, bserver, logo_render):
        response, data = request(bserver, "GET", "/api/v1/logo/backdrop")
        logo = request(bserver, "GET", "/static/logo.png")[0]
        assert (response.status, data) == (200, BACKDROP_JPEG)
        assert response.getheader("Content-Type") == "image/jpeg"
        assert response.getheader("Cache-Control") == "no-cache"
        assert response.getheader("ETag") == logo.getheader("ETag")
        assert response.getheader("X-Content-Type-Options") == "nosniff"

    def test_a_matching_etag_is_a_304_and_the_render_runs_once(self, bserver, logo_render):
        etag = request(bserver, "GET", "/static/logo.png")[0].getheader("ETag")
        response, data = request(bserver, "GET", "/api/v1/logo/backdrop",
                                 headers={"If-None-Match": etag})
        assert (response.status, data) == (304, b"")
        assert response.getheader("Cache-Control") == "no-cache"
        for _ in range(3):
            assert request(bserver, "GET", "/api/v1/logo/backdrop")[0].status == 200
        assert len(logo_render.calls) == 1

    def test_the_logo_backdrop_needs_no_held_artwork(self, bserver, core):
        core.publish(artwork=None)
        assert request(bserver, "GET", "/api/v1/logo/backdrop")[0].status == 200

    def test_an_unrenderable_logo_is_404(self, make_server):
        server = make_server(backdrops=BackdropStore(Path("x"), render_logo=_Render(None)))
        response, data = request(server, "GET", "/api/v1/logo/backdrop")
        assert (response.status, error_of(data)) == (404, "no_backdrop")

    def test_a_missing_logo_file_is_404(self, make_server, monkeypatch, tmp_path):
        monkeypatch.setattr(hds, "LOGO_PATH", tmp_path / "none.png")
        monkeypatch.setattr(hds, "LOGO_FALLBACK_PATH", tmp_path / "none2.png")
        server = make_server(backdrops=BackdropStore(Path("x"), render_logo=_Render()))
        response, data = request(server, "GET", "/api/v1/logo/backdrop")
        assert (response.status, error_of(data)) == (404, "not_found")

    def test_the_default_store_serves_real_jpegs(self, make_server, core):
        pytest.importorskip("PIL")
        import io
        from PIL import Image
        out = io.BytesIO()
        Image.new("RGB", (64, 64), (200, 30, 30)).save(out, "PNG")
        key = artwork_key("https://provider.example/real.png")
        core.publish(artwork=Artwork("", key, out.getvalue(), "", 0.0))
        server = make_server()
        response, data = request(server, "GET", "/api/v1/artwork/%s/backdrop" % key)
        assert response.status == 200 and data[:2] == b"\xff\xd8"
        assert Image.open(io.BytesIO(data)).size == (320, 240)
        response, data = request(server, "GET", "/api/v1/logo/backdrop")
        assert response.status == 200 and data[:2] == b"\xff\xd8"


def test_sniff_image_type_table():
    assert hds.sniff_image_type(JPEG) == "image/jpeg"
    assert hds.sniff_image_type(b"") == "application/octet-stream"


def test_the_reason_table_matches_the_core_refusals():
    assert hds.REASON_STATUS == {
        "unknown_appliance": 404, "unauthorized": 403, "no_capability": 409, "wrong_state": 409,
        "not_polling": 409, "no_record": 409, "not_focused": 409,
    }
    assert hds.REASON_STATUS_DEFAULT == 409


def test_the_server_never_holds_a_lock_across_a_response(server, core):
    """A request served while another thread keeps publishing completes: the
    snapshot is read without taking the core's condition."""
    stop = threading.Event()

    def churn():
        while not stop.is_set():
            core.publish(polling=True)

    thread = threading.Thread(target=churn, daemon=True)
    thread.start()
    try:
        for _ in range(30):
            assert request(server, "GET", "/api/v1/state")[0].status == 200
    finally:
        stop.set()
        thread.join(2)
