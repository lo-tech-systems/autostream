"""dial_hd_server.py: the HD dial's loopback web server.

Serves the HD page, its static files, the state body and the held artwork on
127.0.0.1 (never through nginx, never on a LAN address). One thread accepts
connections and each connection gets its own thread, so a client that stalls
only ever holds its own thread: every socket carries a short timeout, and
nothing here holds a core or view lock while it reads or writes a socket (the
core's snapshot is a lock-free reference read).

Every request is checked before it is routed: the Host header must name the
loopback address (a guard against DNS rebinding), an Origin header must match
the Host, the request line and body are capped, and a POST must carry the
custom header a cross-site form cannot set. No Access-Control headers are
ever sent.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

import http.server
import json
import logging
import re
import socket
import threading
import time
from pathlib import Path
from urllib.parse import urlsplit

from dial_config import HD_PORT_DEFAULT
from dial_hd_events import SSE_MAX_CLIENTS, serve_events
from dial_hd_state import build_state, dumps

HD_PORT = HD_PORT_DEFAULT       # loopback listener; the page's own address
LOOPBACK_ADDRESS = "127.0.0.1"
CLIENT_WRITE_TIMEOUT_S = 2.0
MAX_BODY = 4096                 # the same cap the management server applies
MAX_REQUEST_LINE = 1024

# Required on every POST; a cross-site form cannot set it and a cross-origin
# fetch would need a preflight this server never answers.
REQUESTED_WITH_HEADER = "X-Requested-With"
REQUESTED_WITH_VALUE = "autostream-hd"

CONTENT_SECURITY_POLICY = (
    "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'"
)

ARTWORK_KEY_RE = re.compile(r"^[0-9a-f]{16}$")
ARTWORK_CACHE_CONTROL = "private, max-age=86400, immutable"

HD_STATIC_ROOT = Path(__file__).resolve().parent / "hd"
_REPO_ROOT = Path(__file__).resolve().parent.parent
THEME_FALLBACK_PATH = _REPO_ROOT / "nginx" / "static" / "theme.css"
LOGO_PATH = Path("/opt/autostream/images/autostream-logo-centred-dark.png")
LOGO_FALLBACK_PATH = _REPO_ROOT / "images" / "autostream-logo-centred-dark.png"

# Refusal reason from a core action to an HTTP status. An unlisted reason
# is a conflict.
REASON_STATUS = {
    "unknown_appliance": 404,
    "unauthorized": 403,
    "no_capability": 409,
    "wrong_state": 409,
    "not_polling": 409,
    "no_record": 409,
    "not_focused": 409,
}
REASON_STATUS_DEFAULT = 409

_HTML = "text/html; charset=utf-8"
_CSS = "text/css; charset=utf-8"
_JS = "text/javascript; charset=utf-8"
_PNG = "image/png"

# The static files, by the name served at /static/<name>: the files are
# resolved from this fixed table, never from the request path.
STATIC_FILES = {
    "hd.css": _CSS,
    "hd.js": _JS,
    "theme.css": _CSS,
    "logo.png": _PNG,
}

# The first bytes of an image, and its type.
_IMAGE_SIGNATURES = (
    (b"\xff\xd8", "image/jpeg"),
    (b"\x89PNG", "image/png"),
    (b"GIF8", "image/gif"),
)


def sniff_image_type(data: bytes) -> str:
    """The image type *data* starts as, else application/octet-stream."""
    for prefix, content_type in _IMAGE_SIGNATURES:
        if data.startswith(prefix):
            return content_type
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "image/webp"
    return "application/octet-stream"


def _etag_matches(header: str | None, etag: str) -> bool:
    if not header:
        return False
    if header.strip() == "*":
        return True
    return any(part.strip().removeprefix("W/") == etag for part in header.split(","))


class _HdHTTPServer(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 16


class HdServer:
    """The loopback listener, its dispatcher and its static and state routes.

    *core* supplies snapshot(); *http_server* the management server whose
    screen settings and recovery status fill in the state body; *panel*, when
    given, a view() mapping for the panel block. *static_root* is the
    directory the page files are served from. *muted_fn* reads the shown mute
    flag for a service name (injected so tests need not touch the volume
    store). *extra_routes* are (method, path, handler[, prefix]) rows added to
    the table."""

    def __init__(
        self, cfg, core, *, http_server=None, panel=None, hub=None, static_root=HD_STATIC_ROOT,
        clock=time.monotonic, wall_clock=time.time, muted_fn=None, extra_routes=(),
        port: int | None = None,
    ) -> None:
        self._cfg = cfg
        self._core = core
        self._http_server = http_server
        self._panel = panel
        self._hub = hub
        self._static_root = Path(static_root)
        self._clock = clock
        self._wall_clock = wall_clock
        if muted_fn is None:
            from dial_volume import shown_muted as muted_fn
        self._muted_fn = muted_fn
        self._port = HD_PORT if port is None else port
        self._stopping = threading.Event()
        self._client_lock = threading.Lock()
        self._clients = 0
        self._lifecycle_lock = threading.Lock()
        self._thread: threading.Thread | None = None
        self._server: _HdHTTPServer | None = None
        # method, path, handler(handler, rest), prefix. Exact paths first,
        # then the longest prefix.
        self._routes = [
            ("GET", "/", self._serve_index, False),
            ("GET", "/static/", self._serve_static, True),
            ("GET", "/api/v1/state", self._get_state, False),
            ("GET", "/api/v1/artwork/", self._get_artwork, True),
            ("GET", "/api/v1/events", self._stream_events, False),
        ]
        for route in extra_routes:
            method, path, handler, *prefix = route
            self._routes.append((method, path, handler, bool(prefix and prefix[0])))
        self._server = _HdHTTPServer((LOOPBACK_ADDRESS, self._port), self._make_handler())
        if hub is not None:
            hub.set_builder(self.build_state_bytes)
            hub.set_client_counter(self.client_count)

    # ---- event-stream clients --------------------------------------------

    def client_count(self) -> int:
        with self._client_lock:
            return self._clients

    def enter(self) -> bool:
        """Count one more event-stream client; False when at the cap."""
        with self._client_lock:
            if self._clients >= SSE_MAX_CLIENTS:
                return False
            self._clients += 1
        if self._hub is not None:
            self._hub.poke()
        return True

    def exit(self) -> None:
        with self._client_lock:
            self._clients = max(0, self._clients - 1)
        if self._hub is not None:
            self._hub.poke()

    # ---- lifecycle -------------------------------------------------------

    @property
    def port(self) -> int:
        """The port actually bound (the real one when 0 was asked for)."""
        return self._server.server_address[1]

    @property
    def stopping(self) -> bool:
        return self._stopping.is_set()

    def start(self) -> None:
        with self._lifecycle_lock:
            if self._thread is not None:
                return
            self._thread = threading.Thread(
                target=self._server.serve_forever, kwargs={"poll_interval": 0.2},
                daemon=True, name="dial-hd",
            )
            self._thread.start()
        logging.info("HD server listening on %s:%d", LOOPBACK_ADDRESS, self.port)

    def stop(self) -> None:
        self._stopping.set()
        with self._lifecycle_lock:
            thread, self._thread = self._thread, None
        if thread is not None:
            self._server.shutdown()
            thread.join(2.0)
        self._server.server_close()

    # ---- the state body --------------------------------------------------

    def _settings(self) -> dict:
        if self._http_server is None:
            return {}
        display = self._http_server.display_config
        return {
            "brightness": display.brightness,
            "sleep_after_s": display.sleep_after_s,
            "always_show_controls": display.always_show_controls,
        }

    def _recovery(self) -> dict:
        if self._http_server is None:
            return {}
        status = self._http_server.get_runtime_status()
        return {
            "active": status.get("recovery_active", False),
            "confirmed": status.get("volume_confirmed", False),
        }

    def build_state_bytes(self, seq: int) -> bytes:
        """The state body for the core's current snapshot, as the wire form.
        Reads only lock-free or briefly locked values, never a core or view
        lock across the build."""
        snapshot = self._core.snapshot()
        warnings = getattr(self._core, "warnings", None)
        descriptors = warnings.descriptors() if warnings is not None else ()
        panel = self._panel.view() if self._panel is not None else None
        muted = self._muted_fn(snapshot.volume_readout[0]) if snapshot.volume_readout[0] else None
        body = build_state(
            snapshot, descriptors=descriptors, panel=panel, settings=self._settings(),
            recovery=self._recovery(), hub_seq=seq, now=self._clock(),
            wall_now=self._wall_clock(), muted=muted,
        )
        return dumps(body).encode("utf-8")

    def current_state(self) -> tuple[int, bytes]:
        """(sequence, wire body) of the state now."""
        if self._hub is not None:
            return self._hub.state()
        seq = self._core.snapshot().seq
        return seq, self.build_state_bytes(seq)

    # ---- request checks --------------------------------------------------

    def host_allowed(self, host: str | None) -> bool:
        """Whether *host* (a Host header value) names this listener on the
        loopback address."""
        if not host:
            return False
        name, sep, port = host.rpartition(":")
        if not sep:
            name = host
        if name.lower() not in (LOOPBACK_ADDRESS, "localhost"):
            return False
        if sep:
            return port == str(self.port)
        return True

    # ---- static files ----------------------------------------------------

    def static_path(self, name: str) -> Path | None:
        """The file behind a static name, or None when the table has none."""
        if name == "index.html":
            return self._static_root / "index.html"
        if name == "theme.css":
            for candidate in (self._static_root / "theme.css", THEME_FALLBACK_PATH):
                if candidate.is_file():
                    return candidate
            return None
        if name == "logo.png":
            for candidate in (LOGO_PATH, LOGO_FALLBACK_PATH):
                if candidate.is_file():
                    return candidate
            return None
        if name in STATIC_FILES:
            return self._static_root / name
        return None

    # ---- route handlers --------------------------------------------------

    def _serve_index(self, handler, rest) -> None:
        self._send_file(handler, "index.html", _HTML)

    def _serve_static(self, handler, rest) -> None:
        content_type = STATIC_FILES.get(rest)
        if content_type is None:
            handler.send_json(404, {"ok": False, "error": "not_found"})
            return
        self._send_file(handler, rest, content_type)

    def _send_file(self, handler, name: str, content_type: str) -> None:
        path = self.static_path(name)
        try:
            info = path.stat() if path is not None else None
            if info is None:
                raise FileNotFoundError(name)
            etag = '"%x-%x"' % (info.st_mtime_ns, info.st_size)
            if _etag_matches(handler.headers.get("If-None-Match"), etag):
                handler.send_bytes(304, b"", None, {"ETag": etag, "Cache-Control": "no-cache"}, page=True)
                return
            data = path.read_bytes()
        except OSError:
            handler.send_json(404, {"ok": False, "error": "not_found"})
            return
        handler.send_bytes(
            200, data, content_type, {"ETag": etag, "Cache-Control": "no-cache"}, page=True,
        )

    def _get_state(self, handler, rest) -> None:
        _seq, body = self.current_state()
        handler.send_bytes(200, body, "application/json", {"Cache-Control": "no-store"})

    def _stream_events(self, handler, rest) -> None:
        if self._hub is None:
            handler.send_json(404, {"ok": False, "error": "not_found"})
            return
        serve_events(handler, self._hub, self)

    def _get_artwork(self, handler, rest) -> None:
        if not ARTWORK_KEY_RE.match(rest):
            handler.send_json(400, {"ok": False, "error": "bad_artwork_key"})
            return
        artwork = self._core.snapshot().artwork
        if artwork is None or artwork.key != rest:
            handler.send_json(404, {"ok": False, "error": "no_artwork"})
            return
        headers = {
            "Cache-Control": ARTWORK_CACHE_CONTROL,
            "ETag": '"%s"' % artwork.key,
        }
        if _etag_matches(handler.headers.get("If-None-Match"), headers["ETag"]):
            handler.send_bytes(304, b"", None, headers)
            return
        handler.send_bytes(200, artwork.data, sniff_image_type(artwork.data), headers)

    # ---- the handler -----------------------------------------------------

    def find_route(self, method: str, path: str):
        """(handler, rest) for *method* and *path*, else (None, allowed
        methods) when the path exists under another method, else (None,
        None)."""
        best = None
        allowed = set()
        for route_method, route_path, fn, prefix in self._routes:
            if prefix:
                if not path.startswith(route_path):
                    continue
                rest = path[len(route_path):]
            else:
                if path != route_path:
                    continue
                rest = ""
            if route_method != method:
                allowed.add(route_method)
                continue
            # Exact beats prefix; among prefixes the longest wins.
            rank = (0 if not prefix else 1, -len(route_path))
            if best is None or rank < best[0]:
                best = (rank, fn, rest)
        if best is not None:
            return best[1], best[2]
        return None, sorted(allowed) or None

    def _make_handler(self) -> type:
        hd = self

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"
            # Applies to reads and writes on this connection alone.
            timeout = CLIENT_WRITE_TIMEOUT_S
            server_version = "autostream-hd"
            sys_version = ""

            def log_message(self, fmt, *args) -> None:
                logging.debug("hd http: " + fmt, *args)

            # ---- responses -----------------------------------------------

            def _common_headers(self, page: bool) -> None:
                self.send_header("X-Content-Type-Options", "nosniff")
                if page:
                    self.send_header("Content-Security-Policy", CONTENT_SECURITY_POLICY)
                    self.send_header("Referrer-Policy", "no-referrer")
                    self.send_header("X-Frame-Options", "DENY")

            def send_bytes(self, status, body, content_type, headers=None, page=False) -> None:
                self.send_response(status)
                if content_type is not None:
                    self.send_header("Content-Type", content_type)
                headers = dict(headers or {})
                headers.setdefault("Cache-Control", "no-store")
                for name, value in headers.items():
                    self.send_header(name, value)
                self._common_headers(page)
                if status != 304:
                    self.send_header("Content-Length", str(len(body)))
                self.send_header("Connection", "close")
                self.end_headers()
                if body and status != 304:
                    self.wfile.write(body)
                self.close_connection = True

            def send_json(self, status, obj) -> None:
                body = json.dumps(obj, separators=(",", ":")).encode("utf-8")
                self.send_bytes(status, body, "application/json")

            def send_error(self, code, message=None, explain=None) -> None:
                try:
                    slug = http.HTTPStatus(code).phrase.lower().replace(" ", "_").replace("-", "_")
                except ValueError:
                    slug = "error"
                try:
                    self.send_json(code, {"ok": False, "error": slug})
                except OSError:
                    self.close_connection = True

            # ---- request body --------------------------------------------

            def read_json_body(self) -> dict | None:
                """The request's JSON object, or None after answering the
                refusal itself. An empty body is an empty object."""
                length_header = self.headers.get("Content-Length")
                if length_header is None:
                    if self.headers.get("Transfer-Encoding"):
                        self.send_json(411, {"ok": False, "error": "length_required"})
                        return None
                    return {}
                try:
                    length = int(length_header)
                except ValueError:
                    length = -1
                if length < 0:
                    self.send_json(400, {"ok": False, "error": "bad_content_length"})
                    return None
                if length > MAX_BODY:
                    self.send_json(413, {"ok": False, "error": "body_too_large"})
                    return None
                raw = self.rfile.read(length) if length else b""
                if not raw.strip():
                    return {}
                try:
                    value = json.loads(raw.decode("utf-8"))
                except (ValueError, UnicodeDecodeError):
                    self.send_json(400, {"ok": False, "error": "bad_json"})
                    return None
                if not isinstance(value, dict):
                    self.send_json(400, {"ok": False, "error": "body_must_be_object"})
                    return None
                return value

            # ---- dispatch ------------------------------------------------

            def handle_one_request(self) -> None:
                self.close_connection = True
                try:
                    self.raw_requestline = self.rfile.readline(MAX_REQUEST_LINE + 1)
                    if not self.raw_requestline:
                        return
                    if len(self.raw_requestline) > MAX_REQUEST_LINE:
                        self.requestline = ""
                        self.request_version = ""
                        self.command = ""
                        self.send_json(414, {"ok": False, "error": "request_too_long"})
                        return
                    if not self.parse_request():
                        return
                    self.close_connection = True
                    self._dispatch()
                    self.wfile.flush()
                except (socket.timeout, OSError):
                    self.close_connection = True

            def _dispatch(self) -> None:
                try:
                    self._route()
                except (socket.timeout, OSError):
                    raise
                except Exception:
                    logging.debug("hd request failed", exc_info=True)
                    try:
                        self.send_json(500, {"ok": False, "error": "internal_error"})
                    except OSError:
                        pass

            def _route(self) -> None:
                if not hd.host_allowed(self.headers.get("Host")):
                    self.send_json(403, {"ok": False, "error": "bad_host"})
                    return
                origin = self.headers.get("Origin")
                if origin is not None and origin != "http://" + self.headers.get("Host"):
                    self.send_json(403, {"ok": False, "error": "bad_origin"})
                    return
                path = urlsplit(self.path).path
                fn, rest = hd.find_route(self.command, path)
                if fn is None:
                    if rest:
                        body = json.dumps({"ok": False, "error": "method_not_allowed"}).encode()
                        self.send_bytes(405, body, "application/json", {"Allow": ", ".join(rest)})
                    else:
                        self.send_json(404, {"ok": False, "error": "not_found"})
                    return
                if self.command == "POST" and (
                    self.headers.get(REQUESTED_WITH_HEADER) != REQUESTED_WITH_VALUE
                ):
                    self.send_json(403, {"ok": False, "error": "missing_request_header"})
                    return
                fn(self, rest)

        return Handler
