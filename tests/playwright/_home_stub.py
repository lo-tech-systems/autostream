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
"""
from __future__ import annotations

import json
import sys
import threading
from contextlib import ExitStack
from http.server import BaseHTTPRequestHandler, HTTPServer
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

_BANNER_KEYS = ("stylus", "belt", "bearing", "dial_update", "sample_rate")


def _parsed_config(show_input_detail: bool) -> MagicMock:
    parsed = MagicMock()
    parsed.owntone.base_url = "http://localhost:3689"
    parsed.owntone.output_name = "autostream"
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
) -> bytes:
    """Render the Home page as the server would.

    ``banners`` maps a banner name (stylus, belt, bearing, dial_update,
    sample_rate) to the text the server renders into it; names left out
    render empty. ``levels`` is what the input levels lookup returns; the
    sample rate banner links to the lowest-numbered level that reports a
    mismatch.
    """
    banners = dict(banners or {})
    unknown = set(banners) - set(_BANNER_KEYS)
    if unknown:
        raise ValueError(f"unknown banner name(s): {sorted(unknown)}")

    sys.path.insert(0, str(REPO_ROOT / "core"))
    from autostream_webui_page_airplay import send_airplay_page  # noqa: PLC0415
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
            patch("autostream_webui_page_airplay._config_snapshot",
                  return_value=_parsed_config(show_input_detail)),
            patch("autostream_webui_page_airplay.get_appliance_id", return_value="0" * 20),
            patch("autostream_webui_page_airplay.get_all_appliances", return_value=[]),
            patch("autostream_webui_page_airplay.get_system_hostname", return_value="autostream"),
            fake_playback(snap),
            patch("autostream_webui_page_airplay._dial_update_banner_text",
                  return_value=banners.get("dial_update", "")),
            fake_outputs_result(MagicMock(ok=False, outputs=[])),
            patch("autostream_webui_page_airplay.get_setting",
                  return_value=MagicMock(ok=True, value="2250")),
            fake_track(disabled_snapshot()),
            patch("autostream_webui_page_airplay.build_top_banner_html", return_value=("", "")),
        ):
            stack.enter_context(p)
        send_airplay_page(handler, state, auth)
    return b"".join(chunks)


def render_remote_home(appliance_id: str = REMOTE_APPLIANCE_ID) -> bytes:
    """Render the remote (federated) Home shell for ``appliance_id``."""
    sys.path.insert(0, str(REPO_ROOT / "core"))
    from autostream_webui_page_airplay import send_remote_home_page  # noqa: PLC0415

    handler, chunks = _fake_handler()
    state = MagicMock()
    state.config_path = "dummy.ini"
    with patch("autostream_webui_page_airplay._config_snapshot",
               return_value=_parsed_config(False)), \
         patch("autostream_webui_page_airplay.get_appliance_id", return_value="0" * 20), \
         patch("autostream_webui_page_airplay.get_all_appliances", return_value=[]), \
         patch("autostream_webui_page_airplay.get_system_hostname", return_value="autostream"):
        send_remote_home_page(handler, state, appliance_id)
    return b"".join(chunks)


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
        elif path in API:
            self._send(json.dumps(API[path]).encode(), "application/json")
        elif self.path.startswith("/api/"):
            self._send(b'{"ok": true}', "application/json")
        else:
            self._send(PAGE, "text/html; charset=utf-8")

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


def start_server(page_bytes: bytes) -> tuple[HTTPServer, str]:
    """Serve ``page_bytes`` at ``/`` on an ephemeral port; return the server and its URL."""
    set_page(page_bytes)
    server = HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, f"http://127.0.0.1:{server.server_address[1]}"
