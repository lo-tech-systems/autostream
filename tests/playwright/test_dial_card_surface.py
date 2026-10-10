"""Playwright tests: the Setup > Dials card follows the dial's screen surface.

The page and the Dials panel body come from the real renderer with one
authorized, online dial; the dial's /screen/settings answers are stubbed per
test. A kiosk dial shows brightness and sleep rows and loses the SPI-only
rows and the "Show dial screen" button; an SPI dial (or an old dial that
sends no surface) keeps the SPI rows and gets no HD fields in its save.
"""
from __future__ import annotations

import io
import json
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from types import SimpleNamespace
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
UUID = "dial-aaaa-1111"

_requires_browser = pytest.mark.skipif(
    not _PLAYWRIGHT_INSTALLED, reason="playwright not installed"
)

_CONFIG = json.dumps({
    "general": {"fifo_path": "/tmp/autostream.fifo"},
    "audio1": {"capture_device": "hw:0,0"},
    "owntone": {"output_name": "Living Room"},
})


class _Capture:
    def __init__(self) -> None:
        self._buf = io.BytesIO()
        self.headers: dict = {}
        self._pending_set_cookies: list = []
        self._csrf_token = ""

    def send_response(self, code): pass
    def send_header(self, key, value): pass
    def end_headers(self): pass

    @property
    def wfile(self):
        return self._buf


def _render() -> tuple[bytes, bytes]:
    sys.path.insert(0, str(REPO_ROOT / "core"))
    from autostream_webui_state import WebUIState  # noqa: PLC0415
    from autostream_webui_page_setup import handle_setup_card_get, send_setup_page  # noqa: PLC0415

    auth = MagicMock()
    auth.get_csrf_token.return_value = ""
    auth.get_boot_pin_value.return_value = None
    outputs = SimpleNamespace(ok=True, outputs=[])
    sighting = SimpleNamespace(
        uuid=UUID, name="Hall Dial", version="2.0.0", pin_recovery=False,
        ip="10.0.0.42", dial_proto="v3", sdmon=False,
    )
    entry = SimpleNamespace(uuid=UUID, name="Hall Dial", current_name="Hall Dial", last_seen="")
    with tempfile.TemporaryDirectory() as tmp:
        cfg = Path(tmp) / "config.json"
        cfg.write_text(_CONFIG, encoding="utf-8")
        state = WebUIState(str(cfg), str(Path(tmp) / "state.json"))
        with patch("autostream_webui_page_setup.list_outputs", return_value=outputs), \
             patch("autostream_webui_page_setup.get_ap_ssid", return_value="autostream-setup"), \
             patch("autostream_webui_page_setup.get_system_hostname", return_value="autostream"), \
             patch("autostream_webui_page_setup.suggested_silence_threshold_dbfs", return_value=-50.0), \
             patch("autostream_webui_page_setup.get_app_version", return_value="2.0.0"), \
             patch("autostream_webui_page_setup.parse_dial_entries", return_value=[entry]), \
             patch("autostream_webui_page_setup._get_dial_sightings", return_value=[sighting]):
            page_h = _Capture()
            send_setup_page(page_h, state, auth)
            card_h = _Capture()
            handle_setup_card_get(card_h, state, auth, "dials")
    return page_h.wfile.getvalue(), card_h.wfile.getvalue()


_PAGE: bytes = b""
_CARD: bytes = b""
_SETTINGS: dict = {}
_POSTS: list = []


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
        elif self.path.startswith("/api/setup/card/dials"):
            self._send(_CARD, "application/json")
        elif self.path.startswith("/api/dial/screen/settings/"):
            self._send(json.dumps(_SETTINGS).encode(), "application/json")
        elif self.path.startswith("/api/"):
            self._send(b'{"ok": true, "outputs": []}', "application/json")
        else:
            self._send(_PAGE, "text/html; charset=utf-8")

    def do_POST(self) -> None:
        n = int(self.headers.get("Content-Length", "0"))
        _POSTS.append(json.loads(self.rfile.read(n) or b"{}"))
        self._send(json.dumps(_SETTINGS).encode(), "application/json")

    def log_message(self, *_a) -> None:
        pass


@pytest.fixture(scope="module")
def dial_url():
    global _PAGE, _CARD
    _PAGE, _CARD = _render()
    server = HTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()


def _body(surface: str | None, *, hd_fields: bool = True) -> dict:
    screen = {
        "fitted": True, "rotate": False, "bgr": False, "screen_type": "hd_kiosk" if surface == "kiosk" else "st7735s",
        "touch_type": "none", "screen_size_inches": None, "layout_size": None,
        "always_show_controls": False, "volume_scope": "current", "mute_scope": "current",
    }
    if surface is not None:
        screen["surface"] = surface
    if hd_fields:
        screen["sleep_after_s"] = 900
        screen["brightness"] = 45
    return {
        "ok": True,
        "screen": screen,
        "supported": [{"key": "st7735s", "text": "ST7735S", "default_inches": 1.8},
                      {"key": "hd_kiosk", "text": "HD touchscreen", "default_inches": 7.0}],
        "supported_touch": [{"key": "none", "text": "None"}],
        "layout_sizes": [],
        "runtime": {"backend": "noop" if surface == "kiosk" else "adafruit_st7735s"},
    }


def _open_dials(page: "Page", base: str, body: dict) -> None:
    _SETTINGS.clear()
    _SETTINGS.update(body)
    _POSTS.clear()
    page.goto(f"{base}/setup")
    page.locator(
        ".setup-list-card", has=page.locator(".setup-list-card-title", has_text="Dials")
    ).first.click()
    page.wait_for_selector(".dial-card")
    page.wait_for_function(
        "document.querySelector('.dial-card').dataset.screenLoaded === '1'"
    )


def _visible(page: "Page", cls: str) -> bool:
    return page.locator(f".dial-card .{cls}").first.is_visible()


@_requires_browser
class TestDialCardSurface:
    def test_kiosk_dial_shows_hd_rows_and_hides_spi_rows(self, page: "Page", dial_url: str):
        _open_dials(page, dial_url, _body("kiosk"))
        assert _visible(page, "dial-screen-brightness-row")
        assert _visible(page, "dial-screen-sleep-row")
        assert page.locator(".dial-card .dial-screen-brightness").input_value() == "45"
        assert page.locator(".dial-card .dial-screen-sleep").input_value() == "900"
        for cls in ("dial-screen-rotate-row", "dial-screen-bgr-row", "dial-screen-size-row",
                    "dial-screen-layout-row", "dial-screen-touch-row", "dial-screen-controls-row",
                    "dial-screen-layout-note", "dial-screen-touch-warning"):
            assert not _visible(page, cls), cls
        expect(page.locator('.dial-card [data-dial-action="show-screen"]')).to_be_hidden()

    def test_spi_dial_is_unchanged(self, page: "Page", dial_url: str):
        _open_dials(page, dial_url, _body("spi"))
        assert _visible(page, "dial-screen-rotate-row")
        assert _visible(page, "dial-screen-size-row")
        assert _visible(page, "dial-screen-controls-row")
        assert not _visible(page, "dial-screen-brightness-row")
        assert not _visible(page, "dial-screen-sleep-row")
        expect(page.locator('.dial-card [data-dial-action="show-screen"]')).to_be_visible()

    def test_old_dial_without_surface_is_spi(self, page: "Page", dial_url: str):
        _open_dials(page, dial_url, _body(None, hd_fields=False))
        assert _visible(page, "dial-screen-rotate-row")
        assert not _visible(page, "dial-screen-brightness-row")
        expect(page.locator('.dial-card [data-dial-action="show-screen"]')).to_be_visible()

    def test_kiosk_save_sends_hd_fields(self, page: "Page", dial_url: str):
        _open_dials(page, dial_url, _body("kiosk"))
        page.locator(".dial-card .dial-screen-sleep").select_option("60")
        page.wait_for_timeout(300)
        assert _POSTS, "no save posted"
        screen = _POSTS[-1]["screen"]
        assert screen["sleep_after_s"] == 60
        assert screen["brightness"] == 45
        assert "surface" not in screen

    def test_spi_save_sends_no_hd_fields(self, page: "Page", dial_url: str):
        _open_dials(page, dial_url, _body("spi"))
        page.locator(".dial-card .dial-screen-rotate").evaluate(
            "el => { el.checked = !el.checked; el.dispatchEvent(new Event('change', {bubbles: true})); }"
        )
        page.wait_for_timeout(300)
        assert _POSTS, "no save posted"
        screen = _POSTS[-1]["screen"]
        assert "sleep_after_s" not in screen
        assert "brightness" not in screen
