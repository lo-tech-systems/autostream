"""tests/test_stream_through_nginx.py

The state change stream through the shipped nginx site, run unprivileged where
nginx is installed: events arrive as they are written, a quiet stream outlives
the general read timeout, the general location is unchanged, the cap's refusal
reaches the client as the tunnelled reply, and a closed client frees its slot.
"""
from __future__ import annotations

import json
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

_CORE = str(Path(__file__).resolve().parent.parent / "core")
if _CORE not in sys.path:
    sys.path.insert(0, _CORE)

import autostream_logging as log_setup
from nginx_helpers import copy_for_unprivileged_check
from stream_helpers import Client, Publisher, RealServer, wait_for
import webui.protocol.hub as proto_hub
import webui.protocol.stream as proto_stream

REPO_ROOT = Path(__file__).resolve().parent.parent
NGINX_DIR = REPO_ROOT / "system" / "nginx"
_STOCK_DIR = Path("/etc/nginx")
_STOCK_FILES = ("fastcgi_params", "mime.types")


def _nginx_ok() -> bool:
    try:
        return subprocess.run(["nginx", "-v"], capture_output=True, timeout=10).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


pytestmark = [
    pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux only"),
    pytest.mark.skipif(not _nginx_ok(), reason="nginx not available"),
    pytest.mark.skipif(
        not all((_STOCK_DIR / n).exists() for n in _STOCK_FILES),
        reason="stock nginx files not found"),
]


class _Nginx:
    """The shipped site, listening on a free port and proxying to a backend."""

    def __init__(self, tmp_path: Path, backend_port: int) -> None:
        for name in _STOCK_FILES:
            (tmp_path / name).write_bytes((_STOCK_DIR / name).read_bytes())
        ports: dict[int, int] = {}
        parts = [NGINX_DIR / "autostream-nginxd.conf",
                 NGINX_DIR / "99-autostream-access-log.conf",
                 NGINX_DIR / "autostream-nginx.conf"]
        includes = [copy_for_unprivileged_check(p, tmp_path, ports) for p in parts]
        site = includes[-1]
        site.write_text(
            site.read_text(encoding="utf-8")
            .replace("http://127.0.0.1:8080", f"http://127.0.0.1:{backend_port}")
            .replace("http://127.0.0.1:9080", f"http://127.0.0.1:{backend_port}"),
            encoding="utf-8")
        self.port = ports[80]
        here = tmp_path.as_posix()
        wrapper = tmp_path / "nginx.conf"
        wrapper.write_text(
            f'pid "{here}/nginx.pid";\n'
            f'error_log "{here}/error.log";\n'
            'worker_processes 1;\n'
            'events {}\n'
            'http {\n'
            f'    access_log "{here}/access.log";\n'
            + "".join(f'    {d} "{here}/{d}_tmp";\n' for d in (
                "client_body_temp_path", "proxy_temp_path", "fastcgi_temp_path",
                "uwsgi_temp_path", "scgi_temp_path"))
            + "".join(f'    include "{p.as_posix()}";\n' for p in includes)
            + '}\n',
            encoding="utf-8")
        self.proc = subprocess.Popen(
            ["nginx", "-p", here, "-c", str(wrapper), "-g", "daemon off;"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        deadline = time.monotonic() + 10.0
        while time.monotonic() < deadline:
            try:
                socket.create_connection(("127.0.0.1", self.port), timeout=0.5).close()
                return
            except OSError:
                time.sleep(0.05)
        self.stop()
        raise RuntimeError("nginx did not start")

    def connect(self, path: str = "/api/v1/events") -> Client:
        sock = socket.create_connection(("127.0.0.1", self.port), timeout=5.0)
        sock.sendall(
            f"GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{self.port}\r\n\r\n".encode())
        return Client(sock)

    def stop(self) -> None:
        self.proc.terminate()
        try:
            self.proc.wait(10)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait(5)


@pytest.fixture
def server(monkeypatch):
    log_setup.reset_for_tests()
    s = RealServer(monkeypatch)
    yield s
    s.close()


@pytest.fixture
def front(server, tmp_path):
    n = _Nginx(tmp_path, server.port)
    yield n
    n.stop()


def test_an_event_reaches_the_client_through_nginx_as_it_is_written(server, front):
    publish = Publisher(server.store)
    c = front.connect()
    try:
        assert c.pull_until(b"event: change")
        assert c.head.startswith("HTTP/1.1 200")
        publish("session")
        t0 = time.monotonic()
        assert wait_for(lambda: (c.pull(0.05), len(c.events()) == 2)[1], 3.0)
        assert time.monotonic() - t0 < 1.0
        assert c.events()[-1]["parts"] == ["session"]
    finally:
        c.close()


def test_a_quiet_stream_outlives_the_general_read_timeout(server, front, monkeypatch):
    monkeypatch.setattr(proto_stream, "HEARTBEAT_S", 20.0)
    publish = Publisher(server.store)
    c = front.connect()
    try:
        assert c.pull_until(b"event: change")
        c.pull(25.0)
        publish("outputs")
        assert wait_for(lambda: (c.pull(0.05), len(c.events()) == 2)[1], 3.0)
        assert c.events()[-1]["parts"] == ["outputs"]
    finally:
        c.close()


def test_the_general_location_still_gives_up_on_a_silent_backend_after_fifteen_seconds(tmp_path):
    silent = socket.socket()
    silent.bind(("127.0.0.1", 0))
    silent.listen(4)
    held = []
    stop = threading.Event()

    def accept():
        silent.settimeout(0.2)
        while not stop.is_set():
            try:
                held.append(silent.accept()[0])
            except OSError:
                pass

    t = threading.Thread(target=accept, daemon=True)
    t.start()
    n = _Nginx(tmp_path, silent.getsockname()[1])
    try:
        c = n.connect("/api/status")
        t0 = time.monotonic()
        assert c.pull_until(b"\r\n\r\n", 25.0)
        took = time.monotonic() - t0
        assert 13.0 < took < 20.0
        assert c.head.startswith("HTTP/1.1 302")
        c.close()
    finally:
        n.stop()
        stop.set()
        t.join(2.0)
        for s in held:
            s.close()
        silent.close()


def test_the_refusal_reaches_the_client_as_the_tunnelled_reply(server, front):
    held = []
    try:
        for _ in range(proto_hub.MAX_STREAMS_PER_ADDRESS):
            c = front.connect()
            held.append(c)
            assert c.pull_until(b"retry: 2000")
        ninth = front.connect()
        held.append(ninth)
        assert ninth.pull_until(b"too_many_from_address")
        assert ninth.head.startswith("HTTP/1.1 200")
        assert "application/json" in ninth.head
        assert json.loads(ninth.body)["error_status"] == 503
    finally:
        for c in held:
            c.close()


def test_closing_the_client_frees_the_slot_within_two_seconds(server, front):
    c = front.connect()
    assert c.pull_until(b"retry: 2000")
    assert wait_for(lambda: server.hub.client_count() == 1, 2.0)
    c.close()
    assert wait_for(lambda: server.hub.client_count() == 0, 2.0)
