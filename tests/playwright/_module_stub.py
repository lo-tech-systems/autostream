"""A blank page and the static files, for tests of the shared ES modules.

``start_blank_server()`` serves an empty HTML page at ``/`` and
``/static/*`` from ``nginx/static``, and returns the server and its base URL.
A test loads the page and imports the module it checks inside it.
"""
from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import _page_stub

_PAGE = b"<!doctype html><html><head><meta charset=\"utf-8\"><title>blank</title></head><body></body></html>"


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        if self.path.startswith("/static/"):
            _page_stub.serve_static(self, self.path)
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(_PAGE)))
        self.end_headers()
        self.wfile.write(_PAGE)

    def log_message(self, *args):
        pass


def start_blank_server() -> tuple[ThreadingHTTPServer, str]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, f"http://127.0.0.1:{server.server_address[1]}"
