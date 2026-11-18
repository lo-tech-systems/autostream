"""Playwright tests: the Auto-Start Speakers card on Setup.

The page and the Playback card come from the real renderers with a stored
set. The card lists each member with its level and a Remove button; removing
one saves the rest as owntone.default_outputs, and the last member cannot be
removed.
"""
from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest
import _page_stub

try:
    from playwright.sync_api import Page, expect  # type: ignore[attr-defined]
    _PLAYWRIGHT_INSTALLED = True
except ImportError:
    _PLAYWRIGHT_INSTALLED = False
    Page = object  # type: ignore[misc,assignment]
    expect = None  # type: ignore[assignment]

_requires_browser = pytest.mark.skipif(not _PLAYWRIGHT_INSTALLED, reason="playwright not installed")

_SET = [{"id": "A", "name": "Lounge", "volume": 30}, {"id": "B", "name": "Kitchen", "volume": 45}]
POSTS: list = []


def _serve(members):
    page = _page_stub.render("setup", default_outputs=members)
    cards = _page_stub.setup_card_json(default_outputs=members)

    class Handler(BaseHTTPRequestHandler):
        def _send(self, body: bytes, ctype: str) -> None:
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:
            if self.path.startswith("/static/"):
                _page_stub.serve_static(self, self.path)
            elif self.path.startswith("/api/setup/card/"):
                self._send(cards.get(self.path.rsplit("/", 1)[-1], b"{}"), "application/json")
            elif self.path.startswith("/api/"):
                self._send(b'{"ok": true}', "application/json")
            else:
                self._send(page, "text/html; charset=utf-8")

        def do_POST(self) -> None:
            posted = json.loads(self.rfile.read(int(self.headers.get("Content-Length", "0"))) or b"{}")
            POSTS.append(posted)
            self._send(json.dumps({"ok": True, "field": posted.get("field"), "value": posted.get("value"),
                                   "live": True}).encode(), "application/json")

        def log_message(self, *_a) -> None:
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, f"http://127.0.0.1:{server.server_address[1]}"


def _open(page: "Page", members):
    POSTS.clear()
    server, base = _serve(members)
    page.goto(f"{base}/setup")
    page.locator(".setup-list-card", has=page.locator(".setup-list-card-title", has_text="Playback")).first.click()
    expect(page.locator("#autostart_members")).to_be_visible()
    return server


@_requires_browser
class TestAutoStartCard:
    def test_each_member_is_listed_with_its_level(self, page: "Page"):
        server = _open(page, _SET)
        try:
            rows = page.locator("#autostart_members .autostart-name")
            expect(rows).to_have_text(["Lounge \u00b7 30%", "Kitchen \u00b7 45%"])
            expect(page.locator("#autostart_help")).to_contain_text(
                "To change it, choose speakers on Home, then tap the pin.")
            expect(page.locator("#autostart_help")).not_to_contain_text("At least one speaker")
            expect(page.locator(".slider-header", has_text="Start volume for other speakers")).to_be_visible()
        finally:
            server.shutdown()

    def test_removing_a_member_saves_the_rest_and_locks_the_last(self, page: "Page"):
        server = _open(page, _SET)
        try:
            page.locator("#autostart_members .autostart-remove[data-name='Lounge']").click()
            expect(page.locator("#autostart_members .autostart-row")).to_have_count(1)
            assert POSTS == [{"field": "owntone.default_outputs",
                              "value": [{"id": "B", "name": "Kitchen", "volume": 45}]}]
            expect(page.locator("#autostart_members .autostart-remove")).to_be_disabled()
            expect(page.locator("#autostart_help")).to_contain_text("At least one speaker is needed.")
        finally:
            server.shutdown()

    def test_a_single_member_has_its_remove_button_disabled(self, page: "Page"):
        server = _open(page, _SET[:1])
        try:
            expect(page.locator("#autostart_members .autostart-remove")).to_be_disabled()
            expect(page.locator("#autostart_help")).to_contain_text("At least one speaker is needed.")
            page.locator("#autostart_members .autostart-remove").click(force=True)
            assert POSTS == []
        finally:
            server.shutdown()
