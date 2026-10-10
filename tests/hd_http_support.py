"""Helpers the HD server's action, settings, panel and development-listener
tests share: a request helper that can set any header and Host, a raw socket
sender, a real management server (never started, port 0) to stand behind the
HD server, and the static files a server needs."""
from __future__ import annotations

import http.client
import json
import os
import socket
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "dial"))

import dial_http_server as dhs
from dial_config import DialConfig

REPO_ROOT = Path(__file__).parent.parent
HEADER = {"X-Requested-With": "autostream-hd", "Content-Type": "application/json"}


def request(port, method, path, body=None, headers=None, host=None, address="127.0.0.1"):
    """(response, data). *body* is bytes, or a JSON-able value. *host*
    replaces the Host header; *headers* None leaves out the custom header
    too, so pass HEADER (or a copy) for a well-formed POST."""
    if body is not None and not isinstance(body, (bytes, bytearray)):
        body = json.dumps(body).encode()
    conn = http.client.HTTPConnection(address, port, timeout=5)
    sent = dict(headers or {})
    conn.putrequest(method, path, skip_host=True)
    conn.putheader("Host", host if host is not None else f"127.0.0.1:{port}")
    for name, value in sent.items():
        conn.putheader(name, value)
    if body is not None:
        conn.putheader("Content-Length", str(len(body)))
    conn.endheaders(body)
    response = conn.getresponse()
    data = response.read()
    conn.close()
    return response, data


def post(port, path, body=None, headers=None, **kwargs):
    merged = dict(HEADER)
    merged.update(headers or {})
    return request(port, "POST", path, body if body is not None else {}, merged, **kwargs)


def raw(port, payload: bytes, timeout=5, address="127.0.0.1") -> bytes:
    with socket.create_connection((address, port), timeout=timeout) as sock:
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


def management_server(pin: str = "", **kwargs):
    """A real management server that is never started and holds no port."""
    cfg = DialConfig(uuid="test-uuid", port=0, pin=pin, **kwargs)
    server = dhs.DialHTTPServer(cfg)
    # The real window announces over mDNS with a subprocess.
    server._recovery_window = dhs.RecoveryWindow(lambda add: None)
    return server


def close_management_server(server) -> None:
    server._server.server_close()


def write_static(root: Path) -> Path:
    """The page files a server serves, the login page being the real one."""
    root.mkdir(exist_ok=True)
    (root / "index.html").write_bytes(b"<!doctype html><title>t</title>")
    (root / "hd.css").write_bytes(b"body{}")
    (root / "hd.js").write_bytes(b"(function(){})();")
    (root / "hd-tables.js").write_bytes(b"export const x = 1;")
    (root / "hd-dom.js").write_bytes(b"export const y = 1;")
    (root / "hd-state.js").write_bytes(b"export const z = 1;")
    (root / "hd-eq.js").write_bytes(b"export const z = 1;")
    (root / "hd-derive.js").write_bytes(b"export const z = 1;")
    (root / "theme.css").write_bytes(b":root{}")
    for name in ("login.html", "login.js"):
        (root / name).write_bytes((REPO_ROOT / "dial" / "hd" / name).read_bytes())
    return root
