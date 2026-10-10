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

import hmac
import http.server
import json
import logging
import re
import secrets
import socket
import threading
import time
from collections import OrderedDict
from pathlib import Path
from urllib.parse import urlsplit

import dial_http_server
from dial_config import (
    BRIGHTNESS_MAX, BRIGHTNESS_MIN, HD_PORT_DEFAULT, SLEEP_AFTER_CHOICES_S,
)
from dial_hd_actions import (
    ACTION_NAME_RE, ACTIONS, Context, InvalidArgument, boolean, integer, prepare,
)
from dial_hd_events import SSE_MAX_CLIENTS, serve_events
from dial_hd_state import build_state, dumps

HD_PORT = HD_PORT_DEFAULT       # loopback listener; the page's own address
HD_DEV_PORT = 7844              # the development listener, when enabled
LOOPBACK_ADDRESS = "127.0.0.1"
DEV_BIND_ADDRESS = "0.0.0.0"
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

# The development listener: a PIN login issues one of these cookies, held in
# memory only.
SESSION_COOKIE = "hd_session"
SESSION_TTL_S = 12 * 3600
SESSION_MAX = 8
SESSION_TOKEN_RE = re.compile(r"^[0-9a-f]{32}$")
PIN_MAX_LENGTH = 64
DEV_HOST_RE = re.compile(r"^[A-Za-z0-9._\-]+$|^\[[0-9A-Fa-f:.]+\]$")
# The only files the development listener serves before a login: the login
# page and what it needs to draw. Nothing else is reachable without a session.
DEV_PUBLIC_STATIC = ("hd.css", "theme.css", "logo.png", "login.js")

INFO_CACHE_S = 10.0
PANEL_ACTIONS = ("wake", "sleep", "activity")
# Actions only the dial's own screen may take, never the development listener.
LOCAL_ONLY_ACTIONS = frozenset({"presence"})
SETTINGS_KEYS = ("brightness", "sleep_after_s", "always_show_controls")

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
    "login.js": _JS,
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


def _one_of(value, choices):
    if isinstance(value, bool) or not isinstance(value, int) or value not in choices:
        raise ValueError
    return value


def _session_cookie(token: str, max_age: int) -> str:
    return "%s=%s; HttpOnly; SameSite=Strict; Path=/; Max-Age=%d" % (
        SESSION_COOKIE, token, max_age,
    )


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
    hd_dev = False              # True on the development listener
    hd_stopping = None          # its event: set when that listener closes


class _StreamGate:
    """What an event stream on the development listener asks: whether to go
    on. It ends with the server, with the listener, and when the session that
    opened it is no longer valid."""

    def __init__(self, hd, listener_stopping, token) -> None:
        self._hd = hd
        self._listener_stopping = listener_stopping
        self._token = token

    def enter(self) -> bool:
        return self._hd.enter()

    def exit(self) -> None:
        self._hd.exit()

    @property
    def stopping(self) -> bool:
        return (
            self._hd.stopping or self._listener_stopping.is_set()
            or not self._hd.session_valid(self._token)
        )


class HdServer:
    """The loopback listener, its dispatcher and its static and state routes.

    *core* supplies snapshot(); *http_server* the management server whose
    screen settings and recovery status fill in the state body; *panel*, when
    given, a view() mapping for the panel block. *static_root* is the
    directory the page files are served from. *muted_fn* reads the shown mute
    flag for a service name (injected so tests need not touch the volume
    store). *info_fn* returns the info page's (label, value) rows. *extra_routes*
    are (method, path, handler[, prefix]) rows added to the table.

    A second listener, the development listener, binds the LAN on *dev_port*
    while set_dev_access(True) holds. It serves the same routes behind a PIN
    login and an in-memory session cookie."""

    def __init__(
        self, cfg, core, *, http_server=None, panel=None, hub=None, static_root=HD_STATIC_ROOT,
        clock=time.monotonic, wall_clock=time.time, muted_fn=None, extra_routes=(),
        port: int | None = None, dev_port: int | None = None, info_fn=None,
        dev_bind_address: str = DEV_BIND_ADDRESS,
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
        self._dev_port = HD_DEV_PORT if dev_port is None else dev_port
        self._dev_bind_address = dev_bind_address
        self._info_fn = info_fn
        self._info_lock = threading.Lock()
        self._info_cache: tuple[float, list] | None = None
        self._ctx = Context(core, http_server)
        # Development listener: the listener, its thread, a flag that ends its
        # event streams, and the sessions (token -> (expiry, pin epoch)).
        self._dev_lock = threading.Lock()
        self._dev_httpd: _HdHTTPServer | None = None
        self._dev_thread: threading.Thread | None = None
        self._dev_stopping = threading.Event()
        self._session_lock = threading.Lock()
        self._sessions: OrderedDict = OrderedDict()
        self._pin_epoch = 0
        self._last_pin: str | None = None
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
            ("GET", "/api/v1/info", self._get_info, False),
            ("GET", "/api/v1/settings", self._get_settings, False),
            ("POST", "/api/v1/settings", self._post_settings, False),
            ("POST", "/api/v1/actions/", self._post_action, True),
            ("POST", "/api/v1/panel/", self._post_panel, True),
        ]
        # Reachable on the development listener only.
        self._dev_routes = [
            ("GET", "/login", self._get_login, False),
            ("POST", "/login", self._post_login, False),
            ("POST", "/logout", self._post_logout, False),
        ]
        for route in extra_routes:
            method, path, handler, *prefix = route
            self._routes.append((method, path, handler, bool(prefix and prefix[0])))
        self._handler_class = self._make_handler()
        self._server = _HdHTTPServer((LOOPBACK_ADDRESS, self._port), self._handler_class)
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
        self._close_dev()
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

    def host_allowed(self, host: str | None, dev: bool = False) -> bool:
        """Whether *host* (a Host header value) names the listener asked
        about: the loopback address on the loopback port, or on the
        development listener any plain host name or address on its port."""
        if not host:
            return False
        name, sep, port = host.rpartition(":")
        if not sep:
            name = host
        if dev:
            return bool(
                sep and port == str(self.dev_port) and DEV_HOST_RE.match(name)
            )
        if name.lower() not in (LOOPBACK_ADDRESS, "localhost"):
            return False
        if sep:
            return port == str(self.port)
        return True

    # ---- the development listener ----------------------------------------

    @property
    def dev_port(self) -> "int | None":
        """The development listener's bound port, or None while it is off."""
        httpd = self._dev_httpd
        return httpd.server_address[1] if httpd is not None else None

    def dev_access_enabled(self) -> bool:
        return self._dev_httpd is not None

    def set_dev_access(self, enabled: bool) -> None:
        """Open or close the development listener. Opening needs a PIN
        (the login is the only way in) and a bindable port; either missing
        leaves it closed. Closing drops every session and ends the event
        streams it carries."""
        if enabled and not self._current_pin():
            logging.warning("HD development access needs a PIN; not opened")
            enabled = False
        if enabled and not self._stopping.is_set():
            self._open_dev()
        else:
            self._close_dev()

    def on_config(self, cfg) -> None:
        """Config listener: follow the development access setting, and drop
        every session when the PIN has changed or been cleared."""
        pin = getattr(cfg, "pin", "") or ""
        revoke = False
        with self._session_lock:
            if self._last_pin is not None and pin != self._last_pin:
                self._pin_epoch += 1
                self._sessions.clear()
                revoke = True
            self._last_pin = pin
        if revoke and self._hub is not None:
            self._hub.publish()      # wakes event streams so they re-check
        self.set_dev_access(bool(getattr(cfg, "hd_dev_access", False)) and bool(pin))

    def _current_pin(self) -> str:
        if self._http_server is None:
            return ""
        return self._http_server.current_pin or ""

    def _open_dev(self) -> None:
        with self._dev_lock:
            if self._dev_httpd is not None:
                return
            self._dev_stopping = threading.Event()
            try:
                httpd = _HdHTTPServer(
                    (self._dev_bind_address, self._dev_port), self._handler_class,
                )
            except OSError as e:
                logging.warning("HD development listener not opened: %s", e)
                return
            httpd.hd_dev = True
            httpd.hd_stopping = self._dev_stopping
            thread = threading.Thread(
                target=httpd.serve_forever, kwargs={"poll_interval": 0.2},
                daemon=True, name="dial-hd-dev",
            )
            self._dev_httpd, self._dev_thread = httpd, thread
            thread.start()
        with self._session_lock:
            if self._last_pin is None:
                self._last_pin = self._current_pin()
        logging.info("HD development listener open on port %d", self.dev_port)

    def _close_dev(self) -> None:
        with self._dev_lock:
            httpd, self._dev_httpd = self._dev_httpd, None
            thread, self._dev_thread = self._dev_thread, None
            self._dev_stopping.set()
        with self._session_lock:
            self._sessions.clear()
        if httpd is None:
            return
        httpd.shutdown()
        if thread is not None:
            thread.join(2.0)
        httpd.server_close()
        if self._hub is not None:
            self._hub.publish()
        logging.info("HD development listener closed")

    # ---- sessions ----------------------------------------------------------

    def _issue_session(self) -> str:
        token = secrets.token_hex(16)
        now = self._clock()
        with self._session_lock:
            self._expire_sessions_locked(now)
            while len(self._sessions) >= SESSION_MAX:
                self._sessions.popitem(last=False)
            self._sessions[token] = (now + SESSION_TTL_S, self._pin_epoch)
        return token

    def _expire_sessions_locked(self, now: float) -> None:
        for token in [t for t, (expiry, _e) in self._sessions.items() if expiry <= now]:
            del self._sessions[token]

    def session_valid(self, token: "str | None") -> bool:
        """Whether *token* is a live session: issued here, not expired, and
        issued under the PIN now in force."""
        if not token or not SESSION_TOKEN_RE.match(token):
            return False
        now = self._clock()
        with self._session_lock:
            self._expire_sessions_locked(now)
            entry = self._sessions.get(token)
            return entry is not None and entry[1] == self._pin_epoch

    def _drop_session(self, token: "str | None") -> None:
        if token:
            with self._session_lock:
                self._sessions.pop(token, None)

    # ---- static files ----------------------------------------------------

    def static_path(self, name: str) -> Path | None:
        """The file behind a static name, or None when the table has none."""
        if name in ("index.html", "login.html"):
            return self._static_root / name
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
        if not handler.server.hd_dev:
            serve_events(handler, self._hub, self)
            return
        gate = _StreamGate(
            self, handler.server.hd_stopping, handler.session_token(),
        )
        serve_events(handler, self._hub, gate)

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


    # ---- actions, settings, info, panel ----------------------------------

    def _post_action(self, handler, rest) -> None:
        if not ACTION_NAME_RE.match(rest) or rest not in ACTIONS:
            handler.send_json(404, {"ok": False, "error": "unknown_action"})
            return
        if rest in LOCAL_ONLY_ACTIONS and handler.server.hd_dev:
            # Presence means a person at the dial's own screen; a remote
            # session must never be able to stand in for that.
            handler.send_json(403, {"ok": False, "error": "local_only"})
            return
        body = handler.read_json_body()
        if body is None:
            return
        try:
            call, args = prepare(rest, body)
        except InvalidArgument as e:
            handler.send_json(400, {"ok": False, "error": "invalid_" + e.field})
            return
        result = call(self._ctx, args)
        if result.accepted:
            handler.send_json(200, {"ok": True})
            return
        reason = result.reason or "wrong_state"
        handler.send_json(
            REASON_STATUS.get(reason, REASON_STATUS_DEFAULT), {"ok": False, "error": reason},
        )

    def _get_settings(self, handler, rest) -> None:
        if self._http_server is None:
            handler.send_json(404, {"ok": False, "error": "not_found"})
            return
        handler.send_json(200, {"ok": True, "screen": self._http_server.screen_report()})

    def _post_settings(self, handler, rest) -> None:
        if self._http_server is None:
            handler.send_json(404, {"ok": False, "error": "not_found"})
            return
        body = handler.read_json_body()
        if body is None:
            return
        if not body or any(key not in SETTINGS_KEYS for key in body):
            handler.send_json(400, {"ok": False, "error": "invalid_field"})
            return
        checks = {
            "brightness": integer(BRIGHTNESS_MIN, BRIGHTNESS_MAX),
            "sleep_after_s": lambda v: _one_of(v, SLEEP_AFTER_CHOICES_S),
            "always_show_controls": boolean,
        }
        for key, value in body.items():
            try:
                checks[key](value)
            except ValueError:
                handler.send_json(400, {"ok": False, "error": "invalid_" + key})
                return
        screen = {
            k: v for k, v in self._http_server.screen_report().items() if k != "surface"
        }
        screen.update(body)
        status, reply = self._http_server.apply_screen_settings(screen)
        if status == 200 and reply.get("ok"):
            handler.send_json(200, {"ok": True, "screen": reply["screen"]})
        elif status == 200:
            handler.send_json(409, {"ok": False, "error": reply.get("error", "refused")})
        else:
            handler.send_json(status, {"ok": False, "error": reply.get("error", "refused")})
        if reply.get("restarting"):
            self._http_server.fire_touch_restart()

    def _get_info(self, handler, rest) -> None:
        now = self._clock()
        with self._info_lock:
            cached = self._info_cache
            if cached is None or now - cached[0] >= INFO_CACHE_S:
                rows = [[str(label), str(value)] for label, value in (
                    self._info_fn() if self._info_fn is not None else ()
                )]
                cached = self._info_cache = (self._clock(), rows)
        handler.send_json(200, {"ok": True, "rows": cached[1]})

    def _post_panel(self, handler, rest) -> None:
        if rest not in PANEL_ACTIONS or self._panel is None:
            handler.send_json(404, {"ok": False, "error": "not_found"})
            return
        if handler.read_json_body() is None:
            return
        if rest == "sleep":
            self._panel.sleep_now()
        elif rest == "wake":
            self._panel.wake()
        else:
            self._panel.touch()
        handler.send_json(200, {"ok": True})

    # ---- development listener login --------------------------------------

    def _get_login(self, handler, rest) -> None:
        self._send_file(handler, "login.html", _HTML)

    def _post_login(self, handler, rest) -> None:
        ip = handler.client_address[0]
        blocked, wait = dial_http_server._pin_check_rate_limit(ip)
        if blocked:
            handler.send_too_many(wait)
            return
        body = handler.read_json_body()
        if body is None:
            return
        pin = body.get("pin")
        expected = self._current_pin()
        if not expected:
            handler.send_json(403, {"ok": False, "error": "login_disabled"})
            return
        if (
            not isinstance(pin, str) or len(pin) > PIN_MAX_LENGTH
            or not hmac.compare_digest(pin.encode("utf-8"), expected.encode("utf-8"))
        ):
            dial_http_server._pin_record_failure(ip)
            blocked, wait = dial_http_server._pin_check_rate_limit(ip)
            if blocked:
                handler.send_too_many(wait)
            else:
                handler.send_json(403, {"ok": False, "error": "wrong_pin"})
            return
        dial_http_server._pin_clear_attempts(ip)
        token = self._issue_session()
        handler.send_bytes(
            200, b'{"ok":true}', "application/json",
            {"Set-Cookie": _session_cookie(token, SESSION_TTL_S)},
        )

    def _post_logout(self, handler, rest) -> None:
        if handler.read_json_body() is None:
            return
        self._drop_session(handler.session_token())
        handler.send_bytes(
            200, b'{"ok":true}', "application/json", {"Set-Cookie": _session_cookie("", 0)},
        )

    # ---- the handler -----------------------------------------------------

    def find_route(self, method: str, path: str, dev: bool = False):
        """(handler, rest) for *method* and *path*, else (None, allowed
        methods) when the path exists under another method, else (None,
        None)."""
        best = None
        allowed = set()
        routes = self._routes + self._dev_routes if dev else self._routes
        for route_method, route_path, fn, prefix in routes:
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

            def send_too_many(self, wait: int) -> None:
                body = json.dumps({"ok": False, "error": "too_many_attempts"}).encode()
                self.send_bytes(429, body, "application/json", {"Retry-After": str(int(wait))})

            def session_token(self) -> "str | None":
                """The session cookie's value, or None."""
                for part in (self.headers.get("Cookie") or "").split(";"):
                    name, sep, value = part.strip().partition("=")
                    if sep and name == SESSION_COOKIE:
                        return value
                return None

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
                dev = self.server.hd_dev
                if not hd.host_allowed(self.headers.get("Host"), dev):
                    self.send_json(403, {"ok": False, "error": "bad_host"})
                    return
                origin = self.headers.get("Origin")
                if origin is not None and origin != "http://" + self.headers.get("Host"):
                    self.send_json(403, {"ok": False, "error": "bad_origin"})
                    return
                path = urlsplit(self.path).path
                fn, rest = hd.find_route(self.command, path, dev)
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
                if dev and not self._dev_authorised(path):
                    return
                fn(self, rest)

            def _dev_authorised(self, path: str) -> bool:
                """Development listener only: whether the request may go on.
                The login routes and the login page's own files are open;
                everything else needs a live session. Answers the refusal
                itself when not."""
                if path in ("/login", "/logout"):
                    return True
                if self.command == "GET" and path.startswith("/static/") and (
                    path[len("/static/"):] in DEV_PUBLIC_STATIC
                ):
                    return True
                if hd.session_valid(self.session_token()):
                    return True
                if self.command == "GET" and path == "/":
                    self.send_bytes(302, b"", None, {"Location": "/login"})
                else:
                    self.send_json(401, {"ok": False, "error": "login_required"})
                return False

        return Handler
