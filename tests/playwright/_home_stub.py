"""Shared Home page renderer and stub server for the Playwright tests.

The page comes from the real Home renderer; every other request is answered
by a small stub server. ``/static/*`` is served from ``nginx/static`` (through ``_page_stub``),
``/api/owntone/outputs_state`` from ``OUTPUTS``, ``/api/status`` from
``STATUS`` and the remote Home poll from ``REMOTE_HOME``; each is served only
while its dict is non-empty, so a test that leaves one empty sees the plain
``{"ok": true}`` reply every other ``/api/*`` path gets. The module-level
containers are shared by every importer and are mutated in place, never
rebound. ``START_FAILURE``, when non-empty, is added to the outputs reply as its
``start_failure`` field. ``PATHS`` lists the path of every ``/api/*`` GET the
server has answered; ``API`` maps a GET path to the reply it gets, ahead of the
plain ``{"ok": true}``. ``POST_PATHS`` and ``POST_TOKENS`` record, for each POST
or PUT, its path and its ``X-CSRF-Token`` header.

``STREAM`` and ``STREAM_CONNECTS`` drive ``/api/v1/events``. In the default
``"refuse"`` mode the path gets the plain ``{"ok": true}`` reply, which an
event source cannot use, so a page falls back to polling. After
``stream_on()`` the path holds an event stream open: ``push`` writes one
change event to every open stream, ``drop`` ends them, ``refuse_from_now``
returns to the plain reply and ``open_streams`` counts the streams not yet
closed. ``STREAM_CONNECTS`` has one dict per connection (its ``Last-Event-ID``
header, its ``since`` query, ``opened_at`` and ``closed_at``, which stays
``None`` while the connection is open). ``start_server`` and ``set_page``
reset all of it.
"""
from __future__ import annotations

import json
import queue
import select
import socket
import sys
import threading
import time
from contextlib import ExitStack
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit
from pathlib import Path
from unittest.mock import MagicMock, patch
from fake_store import fake_outputs_result

import _page_stub

REPO_ROOT = Path(__file__).parent.parent.parent

REMOTE_APPLIANCE_ID = "aabbccdd1122334455aa"

PAGE: bytes = b""
OUTPUTS: list = []
REPLIES: list = []
POSTS: list = []
POLLS: list = []
STATUS: dict = {}
STATUS_POLLS: list = []
REMOTE_HOME: dict = {}
REMOTE_HOME_POLLS: list = []
START_FAILURE: dict = {}
PATHS: list = []
API: dict = {}
POST_PATHS: list = []
POST_TOKENS: list = []
STREAM: dict = {"mode": "refuse", "boot": "0123456789abcdef", "version": 1000}
STREAM_CONNECTS: list = []
_STREAM_QUEUES: list = []
_STREAM_LOCK = threading.Lock()

_BANNER_KEYS = ("stylus", "belt", "bearing", "dial_update", "sample_rate")


def _parsed_config(show_input_detail: bool) -> MagicMock:
    parsed = MagicMock()
    parsed.owntone.base_url = "http://localhost:3689"
    from autostream_config import DefaultOutput
    parsed.owntone.default_outputs = (DefaultOutput("", "autostream", 20),)
    parsed.owntone.volume_percent = 20
    parsed.webui.show_master_volume = False
    parsed.webui.show_input_detail = show_input_detail
    parsed.webui.show_hostname_on_home = False
    parsed.webui.control_other_appliances = False
    parsed.webui.hidden_outputs = []
    parsed.webui.dark_mode = False
    parsed.track_identification = MagicMock(enabled=False)
    return parsed


def _fake_handler() -> tuple[MagicMock, list]:
    handler = MagicMock()
    chunks: list = []
    handler.wfile.write = lambda d: chunks.append(d)
    handler._csrf_token = "t"
    handler._pending_set_cookies = []
    return handler, chunks


def render_home(
    *,
    banners: dict[str, str] | None = None,
    levels: list[dict] | None = None,
    show_input_detail: bool = False,
    outputs: list[dict] | None = None,
) -> bytes:
    """Render the Home page as the server would.

    ``banners`` maps a banner name (stylus, belt, bearing, dial_update,
    sample_rate) to the text the server renders into it; names left out
    render empty. ``levels`` is what the input levels lookup returns; the
    sample rate banner links to the lowest-numbered level that reports a
    mismatch. ``outputs`` is the speaker list the page is rendered with (the
    row dicts the list poll carries); without it the player is unreachable.
    """
    banners = dict(banners or {})
    unknown = set(banners) - set(_BANNER_KEYS)
    if unknown:
        raise ValueError(f"unknown banner name(s): {sorted(unknown)}")

    sys.path.insert(0, str(REPO_ROOT / "core"))
    from webui.browser.home import send_airplay_page  # noqa: PLC0415
    from track_id.models import disabled_snapshot  # noqa: PLC0415

    handler, chunks = _fake_handler()
    auth = MagicMock()
    auth.get_csrf_token.return_value = "t"
    state = MagicMock()
    state.config_path = "dummy.ini"

    mismatching = [
        int(lv["index"]) for lv in (levels or [])
        if lv.get("rate_mismatch_hz", 0) and "index" in lv
    ]
    mismatch_input = min(mismatching) if mismatching else 0

    snap = MagicMock()
    snap.inputs = {}
    snap.stylus_banner_text = banners.get("stylus", "")
    snap.belt_banner_text = banners.get("belt", "")
    snap.bearing_banner_text = banners.get("bearing", "")
    snap.has_warning = False
    snap.to_public_dict.return_value = {}

    sys.path.insert(0, str(REPO_ROOT / "tests"))
    from fake_store import FakeStore, fake_playback, fake_track  # noqa: PLC0415

    fake = FakeStore()
    fake.inputs(
        [fake.input_entry(lv["index"], **{k: v for k, v in lv.items() if k != "index"})
         for lv in (levels or [])],
        mismatch=mismatch_input, banner=banners.get("sample_rate", ""))

    with ExitStack() as stack:
        for p in (
            patch("webui.common._config_snapshot",
                  return_value=_parsed_config(show_input_detail)),
            patch("autostream_rpi.get_appliance_id", return_value="0" * 20),
            patch("webui.browser.home.get_all_appliances", return_value=[]),
            patch("webui.browser.home.get_system_hostname", return_value="autostream"),
            fake_playback(snap),
            patch("webui.browser.home._dial_update_banner_text",
                  return_value=banners.get("dial_update", "")),
            fake_outputs_result(
                MagicMock(ok=outputs is not None, outputs=[{"id": "tv", "name": "Speaker A"}])),
            *([patch("webui.browser.home.build_output_list", return_value=list(outputs))]
              if outputs is not None else []),
            patch("webui.browser.home.get_setting",
                  return_value=MagicMock(ok=True, value="2250")),
            fake_track(disabled_snapshot()),
            patch("webui.browser.home.build_top_banner_html", return_value=("", "")),
        ):
            stack.enter_context(p)
        send_airplay_page(handler, state, auth)
    return b"".join(chunks)


def render_remote_home(appliance_id: str = REMOTE_APPLIANCE_ID) -> bytes:
    """Render the remote (federated) Home shell for ``appliance_id``."""
    sys.path.insert(0, str(REPO_ROOT / "core"))
    from webui.browser.home import send_remote_home_page  # noqa: PLC0415

    handler, chunks = _fake_handler()
    state = MagicMock()
    state.config_path = "dummy.ini"
    with patch("webui.common._config_snapshot",
               return_value=_parsed_config(False)), \
         patch("autostream_rpi.get_appliance_id", return_value="0" * 20), \
         patch("webui.browser.home.get_all_appliances", return_value=[]), \
         patch("webui.browser.home.get_system_hostname", return_value="autostream"):
        send_remote_home_page(handler, state, appliance_id)
    return b"".join(chunks)


def _peer_closed(sock) -> bool:
    """Whether the client has closed (or reset) its end of *sock*. A client
    that is merely quiet is not."""
    try:
        if not select.select([sock], [], [], 0)[0]:
            return False
        return sock.recv(1, socket.MSG_PEEK) == b""
    except (OSError, ValueError):
        return True


def reset_stream() -> None:
    """Back to the default mode (refuse), with no stream open and no record."""
    with _STREAM_LOCK:
        for events in _STREAM_QUEUES:
            events.put(None)
        _STREAM_QUEUES.clear()
        STREAM_CONNECTS.clear()
        STREAM["mode"] = "refuse"
        STREAM["version"] = 1000


def stream_on() -> None:
    """Serve event streams from now on."""
    STREAM["mode"] = "serve"


def refuse_from_now() -> None:
    """Answer the next stream requests with the plain reply (streams already open stay)."""
    STREAM["mode"] = "refuse"


def push(parts, *, resync: bool = False) -> None:
    """Write one change event naming *parts* to every open stream."""
    with _STREAM_LOCK:
        STREAM["version"] += 1
        version = STREAM["version"]
        data = json.dumps(
            {"boot": STREAM["boot"], "version": version, "parts": list(parts), "resync": bool(resync)},
            separators=(",", ":"))
        chunk = f"id: {STREAM['boot']}-{version}\nevent: change\ndata: {data}\n\n".encode()
        for events in _STREAM_QUEUES:
            events.put(chunk)


def drop() -> None:
    """End every open stream from the server side."""
    with _STREAM_LOCK:
        for events in _STREAM_QUEUES:
            events.put(None)


def open_streams() -> int:
    """The number of streams not yet closed."""
    with _STREAM_LOCK:
        return sum(1 for r in STREAM_CONNECTS if r["closed_at"] is None)


class Handler(BaseHTTPRequestHandler):
    def _send(self, body: bytes, ct: str) -> None:
        self.send_response(200)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        path = self.path.split("?", 1)[0]
        if path.startswith("/api/"):
            PATHS.append(path)
        if self.path.startswith("/static/"):
            _page_stub.serve_static(self, self.path)
        elif self.path.startswith("/api/owntone/outputs_state"):
            POLLS.append(1)
            reply = {"ok": True, "outputs": OUTPUTS}
            if START_FAILURE:
                reply["start_failure"] = dict(START_FAILURE)
            self._send(json.dumps(reply).encode(), "application/json")
        elif self.path.startswith("/api/status") and STATUS:
            STATUS_POLLS.append(1)
            self._send(json.dumps(STATUS).encode(), "application/json")
        elif path.startswith("/api/appliances/") and path.endswith("/home") and REMOTE_HOME:
            REMOTE_HOME_POLLS.append(1)
            self._send(json.dumps(REMOTE_HOME).encode(), "application/json")
        elif path == "/api/v1/events" and STREAM["mode"] == "serve":
            self._serve_stream()
        elif path in API:
            self._send(json.dumps(API[path]).encode(), "application/json")
        elif self.path.startswith("/api/"):
            self._send(b'{"ok": true}', "application/json")
        else:
            self._send(PAGE, "text/html; charset=utf-8")

    def _serve_stream(self) -> None:
        """Hold an event stream open until the test drops it or the client closes."""
        events: queue.Queue = queue.Queue()
        record = {
            "last_event_id": self.headers.get("Last-Event-ID"),
            "since": (parse_qs(urlsplit(self.path).query).get("since") or [None])[0],
            "opened_at": time.monotonic(),
            "closed_at": None,
        }
        with _STREAM_LOCK:
            STREAM_CONNECTS.append(record)
            _STREAM_QUEUES.append(events)
        try:
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.close_connection = True
            self.wfile.write(b"retry: 100\n\n")
            self.wfile.flush()
            while True:
                try:
                    chunk = events.get(timeout=0.1)
                except queue.Empty:
                    if _peer_closed(self.connection):
                        break
                    continue
                if chunk is None:
                    break
                self.wfile.write(chunk)
                self.wfile.flush()
        except OSError:
            pass
        finally:
            with _STREAM_LOCK:
                record["closed_at"] = time.monotonic()
                if events in _STREAM_QUEUES:
                    _STREAM_QUEUES.remove(events)

    def do_POST(self) -> None:
        n = int(self.headers.get("Content-Length", "0"))
        POSTS.append(json.loads(self.rfile.read(n) or b"{}"))
        POST_PATHS.append(self.path.split("?", 1)[0])
        POST_TOKENS.append(self.headers.get("X-CSRF-Token", ""))
        reply = REPLIES.pop(0) if REPLIES else {"ok": True}
        self._send(json.dumps(reply).encode(), "application/json")

    do_PUT = do_POST

    def log_message(self, *_a) -> None:
        pass


def set_page(page_bytes: bytes) -> None:
    """Choose the page the stub serves at ``/``."""
    global PAGE
    PAGE = page_bytes
    reset_stream()


def start_server(page_bytes: bytes) -> tuple[ThreadingHTTPServer, str]:
    """Serve ``page_bytes`` at ``/`` on an ephemeral port; return the server and its URL."""
    set_page(page_bytes)
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, f"http://127.0.0.1:{server.server_address[1]}"
