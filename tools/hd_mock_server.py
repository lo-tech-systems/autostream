#!/usr/bin/env python3
"""An offline stand-in for the dial's HD server, for iterating on the page on
a laptop with nothing but Python.

It serves the real page files from dial/hd and the shared theme, and answers
the page's API from the HD test scenario corpus: the state body is built by
the production serialiser, the event stream carries it, artwork is the
corpus's bytes, and every action is accepted and logged. One scenario is
current at a time; it can be switched from the command line, from a script of
timed steps, over HTTP (GET or POST /mock/scenario?name=...), or by an action
that leads somewhere (a replay start moves to the replaying scenario).

    python3 tools/hd_mock_server.py [--port 8080] [--scenario replaying]
                                    [--script tests/hd_scripts/journey.json]
                                    [--list] [--bind 127.0.0.1]

Extra routes, not part of the dial's API:

    GET  /mock/scenarios        the scenario names and the current one
    GET  /mock/scenario?name=x  switch scenario (POST works too)
    GET  /mock/actions          the actions accepted so far, oldest first

Only the serialiser and the corpus are imported from the dial's code, so no
display, imaging or hardware library is needed.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

import argparse
import dataclasses
import http.server
import json
import re
import sys
import threading
import time
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

REPO_ROOT = Path(__file__).resolve().parent.parent
for _p in (REPO_ROOT / "tests", REPO_ROOT / "dial", REPO_ROOT / "core"):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

import hd_scenarios  # noqa: E402
from dial_hd_state import dumps  # noqa: E402

DEFAULT_SCENARIO = "playing_artwork"
DEFAULT_PORT = 8080
HEARTBEAT_S = 15.0
CLIENT_WRITE_TIMEOUT_S = 2.0
MAX_BODY = 4096

# The same policy the dial's server sends with the page, so a page that
# breaks it fails here too.
CONTENT_SECURITY_POLICY = (
    "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'"
)
REQUESTED_WITH = ("X-Requested-With", "autostream-hd")

STATIC_ROOT = REPO_ROOT / "dial" / "hd"
THEME_PATH = REPO_ROOT / "nginx" / "static" / "theme.css"
LOGO_PATH = REPO_ROOT / "images" / "autostream-logo-centred-dark.png"

_HTML = "text/html; charset=utf-8"
_CSS = "text/css; charset=utf-8"
_JS = "text/javascript; charset=utf-8"
STATIC_FILES = {
    "hd.css": (_CSS, STATIC_ROOT / "hd.css"),
    "hd.js": (_JS, STATIC_ROOT / "hd.js"),
    "login.js": (_JS, STATIC_ROOT / "login.js"),
    "theme.css": (_CSS, THEME_PATH),
    "logo.png": ("image/png", LOGO_PATH),
}

# The action names the dial accepts, and the scenario each one leads to when
# the mock is not told otherwise.
ACTIONS = (
    "focus", "output", "eq", "eq_reset", "replay_start", "replay_restart", "replay_stop",
    "repeat_arm", "volume_set", "volume_step", "mute_toggle", "warning_dismiss",
    "dial_restart", "presence",
)
ACTION_LEADS = {
    "replay_start": "replaying",
    "replay_restart": "replaying",
    "replay_stop": "playing_artwork",
}
PANEL_ACTIONS = ("wake", "sleep", "activity")
ACTION_NAME_RE = re.compile(r"^[a-z_]{1,32}$")
ARTWORK_KEY_RE = re.compile(r"^[0-9a-f]{16}$")

INFO_ROWS = [
    ["Dial name", "Lounge dial"],
    ["Firmware", "0.0.0-mock"],
    ["IPv4", "127.0.0.1"],
    ["WiFi", "HomeNet"],
    ["Signal", "Strong"],
    ["Disk free", "5.2 GB"],
    ["SD health", "84%"],
]
SETTINGS_KEYS = ("brightness", "sleep_after_s", "always_show_controls")


def load_script(path) -> list:
    """A script as [(delay_s, scenario), ...]; raises ValueError when a step
    is malformed or names an unknown scenario."""
    steps = json.loads(Path(path).read_text(encoding="utf-8"))
    out = []
    for step in steps:
        try:
            delay, name = step
            delay = float(delay)
        except (TypeError, ValueError):
            raise ValueError(f"bad script step: {step!r}") from None
        if name not in hd_scenarios.SCENARIOS or delay < 0:
            raise ValueError(f"bad script step: {step!r}")
        out.append((delay, name))
    return out


class _QuietServer(http.server.ThreadingHTTPServer):
    """A browser that goes away mid-response is not worth a traceback."""

    daemon_threads = True

    def handle_error(self, request, client_address) -> None:
        if not isinstance(sys.exc_info()[1], OSError):
            super().handle_error(request, client_address)


class MockServer:
    """The mock server as an object, so tests can start one on port 0."""

    def __init__(self, scenario=DEFAULT_SCENARIO, *, port=0, bind="127.0.0.1", script=None,
                 leads=None, log=None) -> None:
        if scenario not in hd_scenarios.SCENARIOS:
            raise ValueError(f"unknown scenario {scenario!r}")
        self._cond = threading.Condition()
        self._scenario = scenario
        self._seq = 1
        self._state_cache = None
        self._actions: list = []
        self._leads = dict(ACTION_LEADS if leads is None else leads)
        self._script = list(script or ())
        self._log = log or (lambda text: None)
        self._stopping = threading.Event()
        self._cut = 0                       # bumped by cut_streams()
        self._overrides: dict = {}          # settings posted since the scenario was set
        self._asleep = None                 # the panel's state once a page has changed it
        self._httpd = _QuietServer((bind, port), self._make_handler())
        self._threads: list = []

    # ---- lifecycle -------------------------------------------------------

    @property
    def port(self) -> int:
        return self._httpd.server_address[1]

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def start(self) -> None:
        serve = threading.Thread(target=self._httpd.serve_forever, kwargs={"poll_interval": 0.1},
                                 name="hd-mock", daemon=True)
        serve.start()
        self._threads.append(serve)
        if self._script:
            player = threading.Thread(target=self._play_script, name="hd-mock-script", daemon=True)
            player.start()
            self._threads.append(player)

    def stop(self) -> None:
        self._stopping.set()
        with self._cond:
            self._cond.notify_all()
        self._httpd.shutdown()
        self._httpd.server_close()
        for thread in self._threads:
            thread.join(timeout=3)

    # ---- the current scenario -------------------------------------------

    @property
    def scenario(self) -> str:
        with self._cond:
            return self._scenario

    def set_scenario(self, name: str, *, keep_changes: bool = False) -> bool:
        """Make *name* current and wake every stream. False when unknown.
        The settings a page posted and the panel's sleep state it changed
        are forgotten unless *keep_changes*."""
        if name not in hd_scenarios.SCENARIOS:
            return False
        with self._cond:
            self._scenario = name
            if not keep_changes:
                self._overrides = {}
                self._asleep = None
            self._seq += 1
            self._state_cache = None
            self._cond.notify_all()
        self._log(f"scenario -> {name}")
        return True

    def cut_streams(self) -> None:
        """End every open event stream (the page should then show its
        disconnected state and reconnect)."""
        with self._cond:
            self._cut += 1
            self._cond.notify_all()

    def actions(self) -> list:
        with self._cond:
            return list(self._actions)

    def _bump(self) -> None:
        with self._cond:
            self._seq += 1
            self._state_cache = None
            self._cond.notify_all()

    def _screen(self) -> dict:
        """The screen settings now: the scenario's, with what a page posted."""
        return {**hd_scenarios.SCENARIOS[self.scenario].settings, **self._overrides}

    def _record(self, action: str, body: dict) -> None:
        with self._cond:
            self._actions.append({"action": action, "body": body, "at": time.time()})

    def _play_script(self) -> None:
        for delay, name in self._script:
            if self._stopping.wait(delay):
                return
            self.set_scenario(name)

    def _state(self) -> tuple:
        """(seq, wire body) of the current scenario, built once per change."""
        with self._cond:
            if self._state_cache is None or self._state_cache[0] != self._seq:
                scenario = hd_scenarios.SCENARIOS[self._scenario]
                panel = {**scenario.panel, **{k: v for k, v in self._overrides.items() if k in scenario.panel}}
                if self._asleep is not None:
                    panel["asleep"] = self._asleep
                scenario = dataclasses.replace(
                    scenario, panel=panel, settings={**scenario.settings, **self._overrides})
                body = scenario.state(hub_seq=self._seq)
                self._state_cache = (self._seq, dumps(body).encode("utf-8"))
            return self._state_cache

    # ---- the HTTP handler ------------------------------------------------

    def _make_handler(self) -> type:
        mock = self

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"
            timeout = 30
            server_version = "autostream-hd-mock"
            sys_version = ""

            def log_message(self, fmt, *args) -> None:
                mock._log("http: " + fmt % args)

            def send_bytes(self, status, body, content_type, headers=None, page=False) -> None:
                self.send_response(status)
                if content_type is not None:
                    self.send_header("Content-Type", content_type)
                for name, value in {"Cache-Control": "no-store", **(headers or {})}.items():
                    self.send_header(name, value)
                self.send_header("X-Content-Type-Options", "nosniff")
                if page:
                    self.send_header("Content-Security-Policy", CONTENT_SECURITY_POLICY)
                    self.send_header("Referrer-Policy", "no-referrer")
                    self.send_header("X-Frame-Options", "DENY")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Connection", "close")
                self.end_headers()
                if body:
                    self.wfile.write(body)
                self.close_connection = True

            def send_json(self, status, obj) -> None:
                self.send_bytes(status, json.dumps(obj, separators=(",", ":")).encode(),
                                "application/json")

            def read_body(self):
                try:
                    length = int(self.headers.get("Content-Length") or 0)
                except ValueError:
                    length = -1
                if length < 0 or length > MAX_BODY:
                    self.send_json(400, {"ok": False, "error": "bad_body"})
                    return None
                raw = self.rfile.read(length) if length else b""
                try:
                    body = json.loads(raw) if raw else {}
                except ValueError:
                    body = None
                if not isinstance(body, dict):
                    self.send_json(400, {"ok": False, "error": "bad_body"})
                    return None
                return body

            def do_GET(self) -> None:
                mock._get(self)

            def do_POST(self) -> None:
                mock._post(self)

        return Handler

    def _send_file(self, handler, content_type: str, path: Path) -> None:
        try:
            data = path.read_bytes()
        except OSError:
            handler.send_json(404, {"ok": False, "error": "not_found"})
            return
        handler.send_bytes(200, data, content_type, {"Cache-Control": "no-cache"}, page=True)

    def _get(self, handler) -> None:
        parts = urlsplit(handler.path)
        path, query = parts.path, parse_qs(parts.query)
        if path == "/":
            self._send_file(handler, _HTML, STATIC_ROOT / "index.html")
        elif path.startswith("/static/") and path[8:] in STATIC_FILES:
            content_type, file = STATIC_FILES[path[8:]]
            self._send_file(handler, content_type, file)
        elif path == "/api/v1/state":
            handler.send_bytes(200, self._state()[1], "application/json")
        elif path == "/api/v1/events":
            self._stream(handler)
        elif path.startswith("/api/v1/artwork/"):
            self._get_artwork(handler, path[len("/api/v1/artwork/"):])
        elif path == "/api/v1/info":
            handler.send_json(200, {"ok": True, "rows": INFO_ROWS})
        elif path == "/api/v1/settings":
            handler.send_json(200, {"ok": True, "screen": self._screen()})
        elif path == "/mock/scenarios":
            handler.send_json(200, {"scenarios": list(hd_scenarios.SCENARIO_NAMES),
                                    "current": self.scenario})
        elif path == "/mock/scenario":
            self._switch(handler, (query.get("name") or [""])[0])
        elif path == "/mock/actions":
            handler.send_json(200, {"actions": self.actions()})
        else:
            handler.send_json(404, {"ok": False, "error": "not_found"})

    def _post(self, handler) -> None:
        parts = urlsplit(handler.path)
        path = parts.path
        if path == "/mock/scenario":
            self._switch(handler, (parse_qs(parts.query).get("name") or [""])[0])
            return
        if handler.headers.get(REQUESTED_WITH[0]) != REQUESTED_WITH[1]:
            handler.send_json(403, {"ok": False, "error": "forbidden"})
            return
        if path.startswith("/api/v1/actions/"):
            name = path[len("/api/v1/actions/"):]
            if not ACTION_NAME_RE.match(name) or name not in ACTIONS:
                handler.send_json(404, {"ok": False, "error": "unknown_action"})
                return
            body = handler.read_body()
            if body is None:
                return
            self._record(name, body)
            self._log(f"action {name} {json.dumps(body)}")
            lead = self._leads.get(name)
            if lead:
                self.set_scenario(lead, keep_changes=True)
            handler.send_json(200, {"ok": True})
        elif path == "/api/v1/settings":
            body = handler.read_body()
            if body is None:
                return
            if not body or any(key not in SETTINGS_KEYS for key in body):
                handler.send_json(400, {"ok": False, "error": "invalid_field"})
                return
            self._record("settings", body)
            with self._cond:
                self._overrides.update(body)
            self._bump()
            handler.send_json(200, {"ok": True, "screen": self._screen()})
        elif path.startswith("/api/v1/panel/") and path[len("/api/v1/panel/"):] in PANEL_ACTIONS:
            if handler.read_body() is None:
                return
            name = path.rsplit("/", 1)[1]
            self._record("panel_" + name, {})
            if name in ("wake", "sleep"):
                with self._cond:
                    self._asleep = name == "sleep"
                self._bump()
            handler.send_json(200, {"ok": True})
        else:
            handler.send_json(404, {"ok": False, "error": "not_found"})

    def _switch(self, handler, name: str) -> None:
        if self.set_scenario(name):
            handler.send_json(200, {"ok": True, "scenario": name})
        else:
            handler.send_json(404, {"ok": False, "error": "unknown_scenario"})

    def _get_artwork(self, handler, key: str) -> None:
        artwork = hd_scenarios.SCENARIOS[self.scenario].snapshot.artwork
        if not ARTWORK_KEY_RE.match(key) or artwork is None or artwork.key != key:
            handler.send_json(404, {"ok": False, "error": "no_artwork"})
            return
        handler.send_bytes(200, artwork.data, "image/png",
                           {"Cache-Control": "private, max-age=86400, immutable",
                            "ETag": '"%s"' % artwork.key})

    def _stream(self, handler) -> None:
        handler.close_connection = True
        handler.connection.settimeout(CLIENT_WRITE_TIMEOUT_S)
        handler.send_response(200)
        handler.send_header("Content-Type", "text/event-stream")
        handler.send_header("Cache-Control", "no-store")
        handler.send_header("X-Accel-Buffering", "no")
        handler.send_header("Connection", "close")
        handler.end_headers()
        with self._cond:
            cut = self._cut
        seen = 0
        try:
            while not self._stopping.is_set():
                seq, body = self._state()
                if seq != seen:
                    seen = seq
                    handler.wfile.write(b"id: %d\nevent: state\ndata: %s\n\n" % (seq, body))
                else:
                    handler.wfile.write(b": ping\n\n")
                handler.wfile.flush()
                with self._cond:
                    self._cond.wait_for(
                        lambda: self._seq != seen or self._cut != cut or self._stopping.is_set(),
                        HEARTBEAT_S,
                    )
                    if self._cut != cut:
                        return
        except OSError:
            return


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Offline mock of the dial's HD server.")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--bind", default="127.0.0.1")
    parser.add_argument("--scenario", default=DEFAULT_SCENARIO)
    parser.add_argument("--script", help="JSON list of [delay_s, scenario] steps")
    parser.add_argument("--list", action="store_true", help="print the scenario names and exit")
    args = parser.parse_args(argv)
    if args.list:
        print("\n".join(hd_scenarios.SCENARIO_NAMES))
        return 0
    try:
        script = load_script(args.script) if args.script else None
        server = MockServer(args.scenario, port=args.port, bind=args.bind, script=script,
                            log=lambda text: print(text, flush=True))
    except (ValueError, OSError) as e:
        print(f"hd_mock_server: {e}", file=sys.stderr)
        return 2
    server.start()
    print(f"HD mock on http://{args.bind}:{server.port}/  scenario={args.scenario}", flush=True)
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        pass
    server.stop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
