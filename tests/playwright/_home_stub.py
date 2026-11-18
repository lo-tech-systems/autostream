"""Shared Home page renderer and stub server for the Playwright tests.

The page comes from the real Home renderer; every other request is answered
by a small stub server. ``/static/*`` is served from ``nginx/static`` (through
``_page_stub``).

The protocol routes serve ``PARTS``, the state parts a test arranges
(``base_parts`` gives a quiet appliance, ``unit`` builds a speaker row):

* ``GET /api/v1/state`` (and ``?parts=``) answers the state body. Every query
  string is kept in ``STATE_FETCHES``.
* ``GET /api/v1/events`` is refused in the default ``"refuse"`` mode (the plain
  ``{"ok": true}`` reply, which an event source cannot use, so a page falls
  back to polling the state). After ``stream_on()`` it holds an event stream
  open: ``push(data, resync=False)`` merges ``data`` (part name -> value) into
  ``PARTS`` and writes one change event to every open stream, ``drop`` ends
  them, ``refuse_from_now`` returns to the plain reply, ``open_streams``
  counts the streams not yet closed and ``new_boot`` starts a new boot id at
  a lower version. ``STREAM_CONNECTS`` has one dict per connection (its
  ``Last-Event-ID`` header, its ``since`` query, ``opened_at`` and
  ``closed_at``, which stays ``None`` while the connection is open).
  ``set_parts`` changes ``PARTS`` and the version without an event, for a page
  that is polling.
* ``POST /api/v1/intents/<name>`` answers ``{"ok": true, ...}`` or the next
  entry of ``REPLIES`` merged over it. ``POSTS`` has the body of each POST or
  PUT, ``POST_PATHS`` its path and ``POST_TOKENS`` its ``X-CSRF-Token``.

The older routes stay for the remote Home page and Setup: ``/api/status`` from
``STATUS`` and ``/api/owntone/outputs_state`` from ``OUTPUTS`` (``START_FAILURE``
is its ``start_failure`` field), the remote Home poll from ``REMOTE_HOME``;
each is served only while its dict is non-empty. ``PATHS`` lists the path of
every ``/api/*`` GET answered, and ``API`` maps a GET path to its reply.
``start_server``, ``set_page`` and ``render_home`` reset the stream.
"""
from __future__ import annotations

import copy
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

import _page_stub

REPO_ROOT = Path(__file__).parent.parent.parent

REMOTE_APPLIANCE_ID = "aabbccdd1122334455aa"

PAGE: bytes = b""
REPLIES: list = []
POSTS: list = []
OUTPUTS: list = []
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
STATE_FETCHES: list = []
REPLY_DELAY_S: list = [0.0]
PARTS: dict = {}
PART_VERSIONS: dict = {}
STREAM: dict = {"mode": "refuse", "boot": "0123456789abcdef", "version": 1000}
STREAM_CONNECTS: list = []
_STREAM_QUEUES: list = []
_STREAM_LOCK = threading.Lock()

_INTENTS = "/api/v1/intents/"


def unit(uid: str = "tv", name: str = "Speaker A", **fields) -> dict:
    """One speaker row of the outputs part, as the state body carries it.
    ``offline=True`` is a unit the player has no row for."""
    offline = fields.pop("offline", False)
    pin_pending = fields.pop("pin_pending", False)
    row = {
        "id": uid, "name": name, "selected": False, "volume": 20, "muted": False,
        "availability": "ok", "cause": "user",
        "reported": None if offline else {"pin_pending": pin_pending},
        "connecting": False, "auto_start": False, "hidden": False,
        "pin_claim": "", "in_use_by": "", "offline": offline,
    }
    row.update(fields)
    return row


def base_parts(**parts) -> dict:
    """A quiet appliance: no session, no speakers, no warnings. Each keyword
    replaces the whole part of that name."""
    base = {
        "session": {"active": False, "source": None},
        "repeat": {"block": None},
        "track": {"entries": {}, "service_enabled": False},
        "inputs": {"entries": [], "sample_rate_mismatch_input": 0, "sample_rate_warning_text": ""},
        "playback": {"inputs": {}},
        "outputs": {
            "units": [], "connected": True, "muted_all": False, "start_failure": None,
            "default_members": [], "default_matches": False, "master_volume": None,
            "selected_count": 0,
        },
        "warnings": {"entries": []},
        "monitor": {"connected": True, "output_trim_db": None},
        "appliance": {"id": "0" * 20, "hostname": "autostream", "configured": True},
    }
    base.update(parts)
    return base


def outputs_part(*units: dict, **fields) -> dict:
    """An outputs part with *units*, the selected ones counted for the master level."""
    selected = [u for u in units if u["selected"]]
    part = base_parts()["outputs"]
    part.update(units=list(units), selected_count=len(selected),
                master_volume=round(sum(u["volume"] for u in selected) / len(selected)) if selected else None)
    part.update(fields)
    return part


def state_body(names=None) -> dict:
    """The state body for the current ``PARTS`` (only *names* when given)."""
    with _STREAM_LOCK:
        parts = {n: copy.deepcopy(v) for n, v in PARTS.items() if names is None or n in names}
        return {
            "boot": STREAM["boot"], "version": STREAM["version"], "protocol": 4,
            "time": time.time(), "clients": 1, "part_versions": dict(PART_VERSIONS), "parts": parts,
        }


def set_parts(**parts) -> None:
    """Change parts without an event: the version moves, as a stream's would."""
    with _STREAM_LOCK:
        STREAM["version"] += 1
        PARTS.update(copy.deepcopy(parts))
        for name in parts:
            PART_VERSIONS[name] = STREAM["version"]


def _parsed_config(show_input_detail: bool, show_master_volume: bool, control_other: bool) -> MagicMock:
    parsed = MagicMock()
    parsed.owntone.base_url = "http://localhost:3689"
    parsed.owntone.volume_percent = 20
    parsed.webui.show_master_volume = show_master_volume
    parsed.webui.show_input_detail = show_input_detail
    parsed.webui.show_hostname_on_home = control_other
    parsed.webui.control_other_appliances = control_other
    parsed.webui.hidden_outputs = []
    parsed.webui.dark_mode = False
    return parsed


def _fake_handler() -> tuple[MagicMock, list]:
    handler = MagicMock()
    chunks: list = []
    handler.wfile.write = lambda d: chunks.append(d)
    handler._csrf_token = "t"
    handler._pending_set_cookies = []
    return handler, chunks


def load_parts(parts: dict | None = None) -> None:
    """Start a fresh stream whose state is ``base_parts()`` with each key of
    *parts* replacing that part."""
    reset_stream()
    with _STREAM_LOCK:
        PARTS.clear()
        PARTS.update(copy.deepcopy(base_parts(**(parts or {}))))
        PART_VERSIONS.clear()
        PART_VERSIONS.update({n: STREAM["version"] for n in PARTS})


def render_home(
    *,
    parts: dict | None = None,
    show_input_detail: bool = False,
    show_master_volume: bool = False,
    control_other: bool = False,
) -> bytes:
    """Render the Home page as the server would, starting from *parts* (each
    key replaces that part of ``base_parts()``). ``PARTS`` becomes what the
    page was rendered with, so the stub's state routes agree with it."""
    sys.path.insert(0, str(REPO_ROOT / "core"))
    from webui.browser.home import send_airplay_page  # noqa: PLC0415

    load_parts(parts)
    handler, chunks = _fake_handler()
    auth = MagicMock()
    auth.get_csrf_token.return_value = "t"
    state = MagicMock()
    state.config_path = "dummy.ini"
    with ExitStack() as stack:
        for p in (
            patch("webui.common._config_snapshot",
                  return_value=_parsed_config(show_input_detail, show_master_volume, control_other)),
            patch("autostream_rpi.get_appliance_id", return_value="0" * 20),
            patch("webui.browser.home.get_all_appliances", return_value=[]),
            patch("webui.browser.home.get_system_hostname", return_value="autostream"),
            patch("webui.browser.home.state_for_page", return_value=state_body()),
            patch("webui.browser.home.get_setting", return_value=MagicMock(ok=True, value="2250")),
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
               return_value=_parsed_config(False, False, False)), \
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
    """Back to the default mode (refuse) and the first boot id and version,
    with no stream open and no record."""
    with _STREAM_LOCK:
        for events in _STREAM_QUEUES:
            events.put(None)
        _STREAM_QUEUES.clear()
        STREAM_CONNECTS.clear()
        STATE_FETCHES.clear()
        STREAM["mode"] = "refuse"
        STREAM["boot"] = "0123456789abcdef"
        STREAM["version"] = 1000
        for name in PART_VERSIONS:
            PART_VERSIONS[name] = 1000


def stream_on() -> None:
    """Serve event streams from now on."""
    STREAM["mode"] = "serve"


def refuse_from_now() -> None:
    """Answer the next stream requests with the plain reply (streams already open stay)."""
    STREAM["mode"] = "refuse"


def new_boot(boot: str = "fedcba9876543210", version: int = 5) -> None:
    """The appliance starts again: a new boot id at a version lower than before,
    with the parts as they are and every part at that version."""
    with _STREAM_LOCK:
        STREAM["boot"] = boot
        STREAM["version"] = version
        for name in PARTS:
            PART_VERSIONS[name] = version


def push(data: dict | None = None, *, resync: bool = False) -> None:
    """Merge *data* (part name -> value) into the parts and write one change
    event carrying it to every open stream. With ``resync=True`` the event
    carries no data and tells the page to read the state again."""
    with _STREAM_LOCK:
        STREAM["version"] += 1
        version = STREAM["version"]
        body = {"boot": STREAM["boot"], "version": version, "resync": bool(resync)}
        if not resync:
            PARTS.update(copy.deepcopy(data or {}))
            for name in data or {}:
                PART_VERSIONS[name] = version
            body["data"] = data or {}
        chunk = (f"id: {STREAM['boot']}-{version}\nevent: change\n"
                 f"data: {json.dumps(body, separators=(',', ':'))}\n\n").encode()
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
        elif path == "/api/v1/state":
            query = urlsplit(self.path).query
            STATE_FETCHES.append(query)
            wanted = parse_qs(query).get("parts")
            names = wanted[0].split(",") if wanted else None
            self._send(json.dumps(state_body(names)).encode(), "application/json")
        elif path == "/api/v1/events" and STREAM["mode"] == "serve":
            self._serve_stream()
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
        path = self.path.split("?", 1)[0]
        POST_PATHS.append(path)
        POST_TOKENS.append(self.headers.get("X-CSRF-Token", ""))
        reply = REPLIES.pop(0) if REPLIES else {}
        if path.startswith(_INTENTS):
            with _STREAM_LOCK:
                STREAM["version"] += 1          # an intent is a change; its reply names the version after it
            envelope = {"ok": True, "error": None, "version": STREAM["version"],
                        "boot": STREAM["boot"], "result": {}}
            envelope.update(reply)
            reply = envelope
        elif not reply:
            reply = {"ok": True}
        time.sleep(REPLY_DELAY_S[0])
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
