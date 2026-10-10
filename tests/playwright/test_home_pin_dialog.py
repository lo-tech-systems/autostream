"""Playwright tests: the Home page PIN dialog pairs and enables in one request.

The page comes from the real Home renderer; the outputs poll and the output
POST are stubbed. Every PIN attempt is one POST carrying the PIN and
selected:true. A wrong PIN shows a note and asks again, a rate-limited reply
shows a counting-down wait with the input disabled, and the poll-driven
prompt leaves a row claimed by a dial alone.
"""
from __future__ import annotations

import io
import json
import sys
import threading
from contextlib import ExitStack
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

try:
    from playwright.sync_api import Page, expect  # type: ignore[attr-defined]
    _PLAYWRIGHT_INSTALLED = True
except ImportError:
    _PLAYWRIGHT_INSTALLED = False
    Page = object  # type: ignore[misc,assignment]
    expect = None  # type: ignore[assignment]

REPO_ROOT = Path(__file__).parent.parent.parent

_requires_browser = pytest.mark.skipif(
    not _PLAYWRIGHT_INSTALLED, reason="playwright not installed"
)


def _render_home() -> bytes:
    sys.path.insert(0, str(REPO_ROOT / "core"))
    from autostream_webui_page_airplay import send_airplay_page  # noqa: PLC0415
    from track_id.models import disabled_snapshot  # noqa: PLC0415

    handler = MagicMock()
    chunks: list = []
    handler.wfile.write = lambda d: chunks.append(d)
    handler._csrf_token = "t"
    handler._pending_set_cookies = []
    auth = MagicMock()
    auth.get_csrf_token.return_value = "t"
    state = MagicMock()
    state.config_path = "dummy.ini"

    parsed = MagicMock()
    parsed.owntone.base_url = "http://localhost:3689"
    parsed.owntone.output_name = "autostream"
    parsed.owntone.volume_percent = 20
    parsed.webui.show_master_volume = False
    parsed.webui.show_input_detail = False
    parsed.webui.show_hostname_on_home = False
    parsed.webui.control_other_appliances = False
    parsed.webui.hidden_outputs = []
    parsed.webui.dark_mode = False
    parsed.track_identification = MagicMock(enabled=False)
    snap = MagicMock()
    snap.inputs = {}
    snap.stylus_banner_text = ""
    snap.belt_banner_text = ""
    snap.bearing_banner_text = ""
    snap.has_warning = False
    snap.to_public_dict.return_value = {}

    with ExitStack() as stack:
        for p in (
            patch("autostream_webui_page_airplay._config_snapshot", return_value=parsed),
            patch("autostream_webui_page_airplay.get_appliance_id", return_value="0" * 20),
            patch("autostream_webui_page_airplay.get_all_appliances", return_value=[]),
            patch("autostream_webui_page_airplay.get_system_hostname", return_value="autostream"),
            patch("autostream_webui_page_airplay.get_monitor_levels_dbfs", return_value=[]),
            patch("autostream_webui_page_airplay.get_playback_snapshot", return_value=snap),
            patch("autostream_webui_page_airplay.list_outputs",
                  return_value=MagicMock(ok=False, outputs=[])),
            patch("autostream_webui_page_airplay.get_setting",
                  return_value=MagicMock(ok=True, value="2250")),
            patch("autostream_core.get_active_track_identification_snapshot",
                  return_value=disabled_snapshot()),
            patch("autostream_webui_page_airplay.build_top_banner_html", return_value=("", "")),
        ):
            stack.enter_context(p)
        send_airplay_page(handler, state, auth)
    return b"".join(chunks)


_PAGE: bytes = b""
_OUTPUTS: list = []
_REPLIES: list = []
_POSTS: list = []
_POLLS: list = []


def _row(**extra) -> dict:
    row = {"id": "tv", "name": "Lounge TV", "selected": False, "volume": 20,
           "pin_pending": False}
    row.update(extra)
    return row


class _Handler(BaseHTTPRequestHandler):
    def _send(self, body: bytes, ct: str) -> None:
        self.send_response(200)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        if self.path.startswith("/static/"):
            rel = self.path.split("?", 1)[0][len("/static/"):]
            f = (REPO_ROOT / "nginx" / "static" / rel).resolve()
            body = f.read_bytes() if f.is_file() else b""
            self._send(body, "text/css" if f.suffix == ".css" else "application/javascript")
        elif self.path.startswith("/api/owntone/outputs_state"):
            _POLLS.append(1)
            self._send(json.dumps({"ok": True, "outputs": _OUTPUTS}).encode(), "application/json")
        elif self.path.startswith("/api/"):
            self._send(b'{"ok": true}', "application/json")
        else:
            self._send(_PAGE, "text/html; charset=utf-8")

    def do_POST(self) -> None:
        n = int(self.headers.get("Content-Length", "0"))
        _POSTS.append(json.loads(self.rfile.read(n) or b"{}"))
        reply = _REPLIES.pop(0) if _REPLIES else {"ok": True}
        self._send(json.dumps(reply).encode(), "application/json")

    def log_message(self, *_a) -> None:
        pass


@pytest.fixture(scope="module")
def home_url():
    global _PAGE
    _PAGE = _render_home()
    server = HTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()


def _open_home(page: "Page", base: str, outputs: list, replies: list, *, cards: bool = True) -> None:
    _OUTPUTS[:] = outputs
    _REPLIES[:] = replies
    _POSTS.clear()
    _POLLS.clear()
    page.goto(f"{base}/")
    if cards:
        page.wait_for_selector("#output_enabled_tv", state="attached")


def _pause_clock(page: "Page") -> None:
    page.clock.pause_at(page.evaluate("Date.now()") / 1000 + 1)


def _toggle_on(page: "Page") -> None:
    page.evaluate(
        "() => { const c = document.getElementById('output_enabled_tv');"
        " c.checked = true; c.dispatchEvent(new Event('change', {bubbles: true})); }"
    )


def _type_pin(page: "Page", digits: str) -> None:
    page.locator("#pinModalInput").fill(digits)


@_requires_browser
class TestHomePinDialog:
    def test_switching_on_a_speaker_that_needs_a_pin_opens_the_dialog_and_one_request_pairs_and_enables(
        self, page: "Page", home_url: str
    ):
        _open_home(page, home_url, [_row()],
                   [{"ok": False, "pin_required": True}, {"ok": True}])
        _toggle_on(page)
        expect(page.locator("#pinModal")).to_have_class("modal-overlay show")
        assert len(_POSTS) == 1
        assert "op" not in _POSTS[0]
        _type_pin(page, "2718")
        page.locator("#pinModalOk").click()
        expect(page.locator("#pinModal")).not_to_have_class("modal-overlay show")
        expect(page.locator("#output_enabled_tv")).to_be_checked()
        assert len(_POSTS) == 2
        second = _POSTS[1]
        assert second["id"] == "tv"
        assert second["op"] == "pin"
        assert second["pin"] == "2718"
        assert second["selected"] is True
        assert second["volume"] == 20
        page.wait_for_timeout(300)
        assert len(_POSTS) == 2

    def test_a_wrong_pin_re_prompts_with_the_note(self, page: "Page", home_url: str):
        _open_home(page, home_url, [_row()],
                   [{"ok": False, "pin_required": True},
                    {"ok": False, "pin_invalid": True},
                    {"ok": True}])
        _toggle_on(page)
        _type_pin(page, "1111")
        page.locator("#pinModalOk").click()
        note = page.locator("#pinModalNote")
        expect(note).to_have_text("That PIN was not accepted. Try again.")
        expect(page.locator("#pinModalInput")).to_have_value("")
        expect(page.locator("#pinModalOk")).to_be_disabled()
        _type_pin(page, "2718")
        page.locator("#pinModalOk").click()
        expect(page.locator("#output_enabled_tv")).to_be_checked()
        assert [p.get("pin") for p in _POSTS[1:]] == ["1111", "2718"]

    def test_a_rate_limited_reply_shows_the_wait_and_counts_down(
        self, page: "Page", home_url: str
    ):
        page.clock.install()
        _open_home(page, home_url, [_row()],
                   [{"ok": False, "pin_required": True},
                    {"ok": False, "error": "rate_limited", "retry_after_s": 3},
                    {"ok": True}])
        _pause_clock(page)
        _toggle_on(page)
        _type_pin(page, "1111")
        page.locator("#pinModalOk").click()
        note = page.locator("#pinModalNote")
        expect(note).to_have_text("Wait 3 seconds before retry")
        expect(page.locator("#pinModalInput")).to_be_disabled()
        expect(page.locator("#pinModalOk")).to_be_disabled()
        page.clock.run_for(1000)
        expect(note).to_have_text("Wait 2 seconds before retry")
        page.clock.run_for(1000)
        expect(note).to_have_text("Wait 1 second before retry")
        assert len(_POSTS) == 2
        page.clock.run_for(1000)
        expect(note).to_be_hidden()
        expect(page.locator("#pinModalInput")).to_be_enabled()
        expect(page.locator("#pinModalOk")).to_be_disabled()
        _type_pin(page, "2718")
        page.locator("#pinModalOk").click()
        expect(page.locator("#output_enabled_tv")).to_be_checked()
        assert len(_POSTS) == 3
        assert _POSTS[2]["pin"] == "2718"

    def test_ok_stays_disabled_under_four_digits_and_letters_are_refused(
        self, page: "Page", home_url: str
    ):
        _open_home(page, home_url, [_row()], [{"ok": False, "pin_required": True}])
        _toggle_on(page)
        field = page.locator("#pinModalInput")
        ok = page.locator("#pinModalOk")
        expect(ok).to_be_disabled()
        field.press_sequentially("12a3")
        expect(field).to_have_value("123")
        expect(ok).to_be_disabled()
        field.press_sequentially("45678999")
        expect(field).to_have_value("12345678")
        expect(ok).to_be_enabled()
        field.fill("12")
        expect(ok).to_be_disabled()
        field.fill("1234")
        expect(ok).to_be_enabled()

    def test_cancel_during_the_wait_closes_the_dialog_and_turns_the_switch_off(
        self, page: "Page", home_url: str
    ):
        page.clock.install()
        _open_home(page, home_url, [_row()],
                   [{"ok": False, "pin_required": True},
                    {"ok": False, "error": "rate_limited", "retry_after_s": 5}])
        _pause_clock(page)
        _toggle_on(page)
        _type_pin(page, "1111")
        page.locator("#pinModalOk").click()
        expect(page.locator("#pinModalNote")).to_have_text("Wait 5 seconds before retry")
        page.locator("#pinModalCancel").click()
        expect(page.locator("#pinModal")).not_to_have_class("modal-overlay show")
        expect(page.locator("#output_enabled_tv")).not_to_be_checked()
        page.clock.run_for(10000)
        expect(page.locator("#pinModal")).not_to_have_class("modal-overlay show")
        assert len(_POSTS) == 2

    def test_the_poll_prompt_skips_a_row_claimed_by_a_dial(self, page: "Page", home_url: str):
        _open_home(page, home_url, [_row(pin_pending=True, pin_claim="dial:x")], [])
        start = len(_POLLS)
        deadline_polls = start + 2
        for _ in range(60):
            if len(_POLLS) >= deadline_polls:
                break
            page.wait_for_timeout(100)
        assert len(_POLLS) >= deadline_polls
        expect(page.locator("#pinModal")).not_to_have_class("modal-overlay show")
        assert _POSTS == []

    def test_the_poll_prompt_opens_for_an_unclaimed_row(self, page: "Page", home_url: str):
        # The open prompt holds back the card render, so there is no card to wait for.
        _open_home(page, home_url, [_row(pin_pending=True, pin_claim="")], [], cards=False)
        expect(page.locator("#pinModal")).to_have_class("modal-overlay show")
