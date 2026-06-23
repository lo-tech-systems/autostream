"""Playwright end-to-end browser tests.

Covers: page rendering, navigation cards, panel interaction, accessibility.

The stub server started by the ``base_url`` fixture serves HTML produced by
the real ``send_setup_page()`` renderer (core/autostream_webui_page_setup.py)
with hardware dependencies mocked out.  Changes to the page template, its
embedded CSS, or its JavaScript therefore break these tests, not just changes
to hand-written HTML.

When AUTOSTREAM_URL is set the tests run against a real appliance instead.

Requirements:
  pip install pytest-playwright && playwright install chromium

CI job: playwright in .github/workflows/ci.yml.
"""
from __future__ import annotations

import io
import json
import os
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

REPO_ROOT = Path(__file__).parent.parent.parent

# ---------------------------------------------------------------------------
# Playwright availability — the only thing that blocks test execution.
# Server availability is handled by the base_url fixture (stub or real).
# ---------------------------------------------------------------------------

try:
    from playwright.sync_api import Page, expect  # type: ignore[attr-defined]
    _PLAYWRIGHT_INSTALLED = True
except ImportError:
    _PLAYWRIGHT_INSTALLED = False
    Page = object  # type: ignore[misc,assignment]
    expect = None  # type: ignore[assignment]

_requires_browser = pytest.mark.skipif(
    not _PLAYWRIGHT_INSTALLED,
    reason=(
        "playwright not installed — "
        "pip install pytest-playwright && playwright install chromium"
    ),
)

# ---------------------------------------------------------------------------
# Production HTML renderer
#
# Calls the real send_setup_page() from core/autostream_webui_page_setup.py
# with all hardware-dependent functions patched to return safe defaults.
# The config written to the temp file satisfies unconfigured() → False so
# that the full page — including the System & Updates section — is rendered.
# ---------------------------------------------------------------------------

# Minimal config that makes unconfigured() return False:
#   general.fifo_path, audio1.capture_device (hw:*), owntone.output_name
_MINIMAL_CONFIG = json.dumps({
    "general": {"fifo_path": "/tmp/autostream.fifo"},
    "audio1":  {"capture_device": "hw:0,0"},
    "owntone": {"output_name": "Living Room"},
})

# Catch-all JSON returned for every /api/* request so the real page's
# polling JavaScript (refreshOwntoneOutputs, update poller, etc.) does not
# raise unhandled promise rejections when the stub has no live backends.
_API_JSON: bytes = json.dumps({
    "ok": True,
    "outputs": [],
    "playing": False,
    "state": "idle",
    "version": "2.0.0",
}).encode("utf-8")


class _CapturingHandler:
    """Minimal HTTP-handler shim that captures the bytes written by send_setup_page()."""

    def __init__(self) -> None:
        self._buf: io.BytesIO = io.BytesIO()
        self.headers: dict = {}
        self._pending_set_cookies: list = []
        self._csrf_token: str = ""

    def send_response(self, code: int) -> None: pass
    def send_header(self, key: str, value: str) -> None: pass
    def end_headers(self) -> None: pass

    @property
    def wfile(self) -> io.BytesIO:
        return self._buf


def _render_production_setup_page() -> bytes:
    """Invoke the real send_setup_page() with mocked hardware deps.

    Returns UTF-8 bytes of the complete HTML that a configured appliance
    serves at /setup.  Any breakage in the production renderer, its CSS, or
    its embedded JavaScript will cause this function to raise or return empty
    bytes, which in turn fails the base_url fixture and all browser tests.
    """
    sys.path.insert(0, str(REPO_ROOT / "core"))

    # Import lazily so the module is only loaded when the stub starts.
    from autostream_webui_state import WebUIState            # noqa: PLC0415
    from autostream_webui_page_setup import send_setup_page  # noqa: PLC0415

    auth = MagicMock()
    auth.get_csrf_token.return_value = ""
    auth.get_boot_pin_value.return_value = None

    outputs_mock = MagicMock()
    outputs_mock.ok = True
    outputs_mock.outputs = []

    with tempfile.TemporaryDirectory() as tmp:
        cfg_path = Path(tmp) / "config.json"
        cfg_path.write_text(_MINIMAL_CONFIG, encoding="utf-8")

        state = WebUIState(str(cfg_path), str(Path(tmp) / "state.json"))
        handler = _CapturingHandler()

        with patch("autostream_webui_page_setup.list_outputs",
                   return_value=outputs_mock), \
             patch("autostream_webui_page_setup.get_ap_ssid",
                   return_value="autostream-setup"), \
             patch("autostream_webui_page_setup.get_system_hostname",
                   return_value="autostream"), \
             patch("autostream_webui_page_setup.set_system_hostname"), \
             patch("autostream_webui_page_setup.suggested_silence_threshold_dbfs",
                   return_value=-50.0), \
             patch("autostream_webui_page_setup.get_app_version",
                   return_value="2.0.0"), \
             patch("autostream_webui_page_setup.parse_dial_entries",
                   return_value=[]), \
             patch("autostream_webui_page_setup._get_dial_sightings",
                   return_value=[]):
            send_setup_page(handler, state, auth)

    html_bytes = handler._buf.getvalue()
    if not html_bytes:
        raise RuntimeError(
            "send_setup_page() produced no output — "
            "check _MINIMAL_CONFIG, mocked dependencies, and autostream_config.py"
        )
    return html_bytes


# ---------------------------------------------------------------------------
# Stub HTTP server
# ---------------------------------------------------------------------------

# Populated once per session by the base_url fixture before the server starts.
_STUB_HTML_BYTES: bytes = b""


class _StubHandler(BaseHTTPRequestHandler):
    """Serve production-rendered HTML for page requests and JSON stubs for /api/."""

    def do_GET(self) -> None:
        if self.path.startswith("/api/"):
            # Return a catch-all JSON response so the real page's XHR polling
            # (refreshOwntoneOutputs, update-status poller, etc.) does not
            # raise unhandled promise rejections.
            body = _API_JSON
            ct = "application/json"
        else:
            body = _STUB_HTML_BYTES
            ct = "text/html; charset=utf-8"
        self.send_response(200)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args) -> None:
        pass


# ---------------------------------------------------------------------------
# base_url fixture — real appliance or auto-started stub
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def base_url():
    """Return the base URL to test against.

    Uses AUTOSTREAM_URL when set (real appliance).  Otherwise renders the
    production setup page HTML with mocked hardware and starts a local stub
    server so CI always has a target without external infrastructure.
    """
    url = os.environ.get("AUTOSTREAM_URL", "").rstrip("/")
    if url:
        yield url
        return

    # Render production HTML once; raise clearly if the renderer is broken.
    global _STUB_HTML_BYTES
    _STUB_HTML_BYTES = _render_production_setup_page()

    server = HTTPServer(("127.0.0.1", 0), _StubHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        server.shutdown()


# ---------------------------------------------------------------------------
# Setup page — structure and navigation cards
#
# Markup comes from the real renderer; selectors must match
# core/autostream_webui_page_setup.py exactly.
#   <title>autostream</title>                          (build_page_html arg)
#   <html data-theme="light|dark">                     (build_page_html arg)
#   <div class="eq-page-header"><h1>Setup</h1></div>  (_setup_page_header)
#   <div class="setup-list-card" onclick="openPanel('...')">
#     <span class="setup-list-card-title">…</span>     (real card structure)
#   </div>
#   <button type="submit" … class="pill-btn small">Save</button>
#   <div class="setup-detail-panel" id="panel-system">…</div>
#   <button id="btnCheck" …>Check</button>             (update controls)
# ---------------------------------------------------------------------------

@_requires_browser
class TestSetupPage:
    def test_setup_page_title_is_autostream(self, page: "Page", base_url: str):
        page.goto(f"{base_url}/setup")
        expect(page).to_have_title("autostream")

    def test_setup_page_h1_contains_setup(self, page: "Page", base_url: str):
        page.goto(f"{base_url}/setup")
        expect(page.locator("h1").first).to_contain_text("Setup")

    def test_setup_page_shows_input1_card(self, page: "Page", base_url: str):
        page.goto(f"{base_url}/setup")
        expect(
            page.locator(".setup-list-card-title", has_text="Input 1")
        ).to_be_visible()

    def test_setup_page_shows_all_nav_cards(self, page: "Page", base_url: str):
        page.goto(f"{base_url}/setup")
        for title in ("Input 1", "Input 2", "Playback", "System"):
            expect(
                page.locator(".setup-list-card-title", has_text=title)
            ).to_be_visible()

    def test_save_button_absent(self, page: "Page", base_url: str):
        """Setup page uses autosave; there is no bulk-save submit button."""
        page.goto(f"{base_url}/setup")
        expect(page.locator("button[type=submit].pill-btn")).not_to_be_visible()

    def test_no_js_errors_on_load(self, page: "Page", base_url: str):
        errors: list[str] = []
        page.on("pageerror", lambda e: errors.append(str(e)))
        page.goto(f"{base_url}/setup")
        page.wait_for_load_state("networkidle")
        assert not errors, f"JavaScript errors on /setup load: {errors}"

    def test_no_js_errors_after_polling_interval(self, page: "Page", base_url: str):
        """Real page polls /api/owntone/outputs every 2 s; stub returns valid JSON."""
        errors: list[str] = []
        page.on("pageerror", lambda e: errors.append(str(e)))
        page.goto(f"{base_url}/setup")
        page.wait_for_timeout(2500)
        assert not errors, f"JavaScript error during polling interval: {errors}"


# ---------------------------------------------------------------------------
# System panel — revealed by clicking the System navigation card
# ---------------------------------------------------------------------------

@_requires_browser
class TestSystemPanel:
    def test_system_card_is_present(self, page: "Page", base_url: str):
        page.goto(f"{base_url}/setup")
        expect(page.locator(".setup-list-card", has=page.locator(
            ".setup-list-card-title", has_text="System"
        ))).to_be_visible()

    def test_clicking_system_card_reveals_panel(self, page: "Page", base_url: str):
        page.goto(f"{base_url}/setup")
        page.locator(".setup-list-card", has=page.locator(
            ".setup-list-card-title", has_text="System"
        )).click()
        # CSS: .setup-detail-panel { display:none } .setup-detail-panel.active { display:block }
        expect(page.locator("#panel-system")).to_be_visible()

    def test_system_panel_contains_update_controls(self, page: "Page", base_url: str):
        """The System panel includes update controls (btnCheck) when fully configured."""
        page.goto(f"{base_url}/setup")
        page.locator(".setup-list-card", has=page.locator(
            ".setup-list-card-title", has_text="System"
        )).click()
        expect(page.locator("#panel-system")).to_be_visible()
        # btnCheck is present when initial_setup=False (our mocked config satisfies this)
        expect(page.locator("#btnCheck")).to_be_attached()


# ---------------------------------------------------------------------------
# Accessibility
# ---------------------------------------------------------------------------

@_requires_browser
class TestAccessibility:
    def test_html_element_has_data_theme(self, page: "Page", base_url: str):
        """build_page_html() sets data-theme='light' or 'dark' on <html>."""
        page.goto(f"{base_url}/setup")
        theme = page.locator("html").get_attribute("data-theme")
        assert theme in ("light", "dark"), (
            f"Expected data-theme='light' or 'dark' on <html>, got {theme!r}"
        )

    def test_no_bulk_save_button_on_setup(self, page: "Page", base_url: str):
        """Setup page uses per-field autosave; no bulk-submit button should exist."""
        page.goto(f"{base_url}/setup")
        expect(page.locator("button[type=submit].pill-btn")).not_to_be_visible()

    def test_nav_card_titles_are_non_empty(self, page: "Page", base_url: str):
        page.goto(f"{base_url}/setup")
        titles = page.locator(".setup-list-card-title").all()
        assert titles, "No .setup-list-card-title elements found on /setup"
        for el in titles:
            assert el.inner_text().strip(), (
                f"A .setup-list-card-title has no text: {el.inner_html()[:80]}"
            )
