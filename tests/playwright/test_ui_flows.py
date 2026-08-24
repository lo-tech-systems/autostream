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


def _render_production_setup_page() -> tuple[bytes, dict[str, bytes]]:
    """Invoke the real send_setup_page() with mocked hardware deps.

    Returns (full_page_html_bytes, {card_key: card_detail_json_bytes}).

    send_setup_page() is summary-rows-plus-empty-panels shaped: the
    nine detail panels are not inlined into the /setup response, so
    the stub server also needs each card's lazy `GET /api/setup/card/<key>`
    response pre-rendered (via handle_setup_card_get()) to serve when the
    real browser-side openPanel() JS fetches it -- without this, panel
    bodies would just show the client's "Could not load this section"
    fallback and every control-presence assertion below would fail.

    Any breakage in the production renderer, its CSS, or its embedded
    JavaScript will cause this function to raise or return empty bytes,
    which in turn fails the base_url fixture and all browser tests.
    """
    sys.path.insert(0, str(REPO_ROOT / "core"))

    # Import lazily so the module is only loaded when the stub starts.
    from autostream_webui_state import WebUIState  # noqa: PLC0415
    from autostream_webui_page_setup import (  # noqa: PLC0415
        CARDS,
        handle_setup_card_get,
        send_setup_page,
    )

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
             patch("autostream_webui_page_setup.suggested_silence_threshold_dbfs",
                   return_value=-50.0), \
             patch("autostream_webui_page_setup.get_app_version",
                   return_value="2.0.0"), \
             patch("autostream_webui_page_setup.parse_dial_entries",
                   return_value=[]), \
             patch("autostream_webui_page_setup._get_dial_sightings",
                   return_value=[]):
            send_setup_page(handler, state, auth)

            card_html: dict[str, bytes] = {}
            for card in CARDS:
                card_handler = _CapturingHandler()
                handle_setup_card_get(card_handler, state, auth, card.key)
                card_html[card.key] = card_handler._buf.getvalue()

    html_bytes = handler._buf.getvalue()
    if not html_bytes:
        raise RuntimeError(
            "send_setup_page() produced no output — "
            "check _MINIMAL_CONFIG, mocked dependencies, and autostream_config.py"
        )
    return html_bytes, card_html


# ---------------------------------------------------------------------------
# Stub HTTP server
# ---------------------------------------------------------------------------

# Populated once per session by the base_url fixture before the server starts.
_STUB_HTML_BYTES: bytes = b""
# Keyed by card key, each value is the JSON body handle_setup_card_get()
# produced for that card ({"ok": true, "html": "..."}), pre-rendered once so
# the stub server can answer the browser's lazy per-card fetch.
_STUB_CARD_JSON: dict = {}


class _StubHandler(BaseHTTPRequestHandler):
    """Serve production-rendered HTML for page requests and JSON stubs for /api/."""

    def do_GET(self) -> None:
        if self.path.startswith("/static/"):
            # Serve the real nginx/static/* files (poll.js, theme.css,
            # render_fragments.js, ...) so scripts the real page's <script
            # src="/static/..."> tags load (e.g. Poller, referenced by the
            # Setup page's activeOnly pollers) actually execute instead
            # of erroring on this server's default (non-static) HTML body.
            rel = self.path.split("?", 1)[0][len("/static/"):]
            static_path = (REPO_ROOT / "nginx" / "static" / rel).resolve()
            static_root = (REPO_ROOT / "nginx" / "static").resolve()
            if static_root in static_path.parents and static_path.is_file():
                body = static_path.read_bytes()
                ct = "text/css" if static_path.suffix == ".css" else "application/javascript"
            else:
                body = b""
                ct = "text/plain"
            self.send_response(200 if body else 404)
            self.send_header("Content-Type", ct)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path.startswith("/api/setup/card/"):
            # Lazy per-card detail fetch: serve the pre-rendered
            # {ok, html} body for this specific card, not the generic
            # catch-all below (which has no "html" key and would leave
            # every panel showing the client's load-failure fallback).
            key = self.path.rsplit("/", 1)[-1]
            body = _STUB_CARD_JSON.get(key, b'{"ok": false, "error": "unknown_card"}')
            ct = "application/json"
        elif self.path.startswith("/api/"):
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
    global _STUB_HTML_BYTES, _STUB_CARD_JSON
    _STUB_HTML_BYTES, _STUB_CARD_JSON = _render_production_setup_page()

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


# ---------------------------------------------------------------------------
# Shared helpers for the lazily-fetched Setup detail panels.
# ---------------------------------------------------------------------------

def _open_setup_panel(page: "Page", title: str) -> None:
    page.locator(
        ".setup-list-card", has=page.locator(".setup-list-card-title", has_text=title)
    ).first.click()


def _close_setup_panel(page: "Page", panel_id: str) -> None:
    page.locator(f"#{panel_id} .setup-detail-back button").click()




# ---------------------------------------------------------------------------
# Lazy per-card detail fetch must not corrupt the other cards' summaries.
#
# Every collapsed summary row is *derived from that card's detail-panel
# controls* by refreshSetupCardSubs(), which the Back button fires. Once the
# panels load lazily, a card the user never opened has no controls in the DOM
# at all -- so an ungated refresh reads every control as absent and rewrites
# the correct server-rendered summary as "Off" / "No speaker selected . 0%" /
# "Not configured". Opening one card and going Back must leave every other
# card's summary exactly as the server rendered it.
# ---------------------------------------------------------------------------

@_requires_browser
class TestLazyPanelsPreserveSummaries:
    def _summaries(self, page: "Page") -> dict:
        return {
            el.get_attribute("id"): el.inner_text()
            for el in page.locator(".setup-list-card-sub").all()
        }

    def test_back_from_one_panel_leaves_other_summaries_intact(
        self, page: "Page", base_url: str
    ):
        page.goto(f"{base_url}/setup")
        page.wait_for_load_state("networkidle")
        before = self._summaries(page)
        assert before.get("track-id-card-sub"), "expected a server-rendered Track ID summary"

        _open_setup_panel(page, "Bluetooth")
        expect(page.locator("#panel-bluetooth")).to_be_visible()
        _close_setup_panel(page, "panel-bluetooth")
        page.wait_for_timeout(250)

        assert self._summaries(page) == before, (
            "closing a panel rewrote other cards' summary rows -- "
            "refreshSetupCardSubs() read never-fetched panels' absent controls"
        )




# ---------------------------------------------------------------------------
# The two confirmed visibility/scope polling bugs, verified in a real
# browser.
#
# Previously the Bluetooth link-status poll and the network-adapter-info poll
# were bare `setInterval(..., 5000)` calls with no visibility check and no tie
# to their own detail panel: both kept hitting the appliance every 5s forever,
# whether or not their panel was open and whether or not the tab was even
# visible. They are now `Poller({activeOnly: true})` instances started by
# openPanel() and stopped by closePanel(), so the poll must be absent before
# the panel is ever opened, present while it is open, and absent again once
# it closes. Asserting only "the source says Poller(...)" would not catch a
# missing .start()/.stop() wiring, which is the part that actually fixes the
# bug -- hence a real browser and real request counting.
# ---------------------------------------------------------------------------

_POLL_WINDOW_MS = 6000  # > the 5s poll interval, so a live poll must fire


def _assert_poll_is_panel_scoped(page: "Page", base_url: str, api_path: str,
                                 card_title: str, panel_id: str) -> None:
    page.goto(f"{base_url}/setup")
    page.wait_for_load_state("networkidle")

    hits: list[str] = []
    page.on("request", lambda r: hits.append(r.url) if api_path in r.url else None)

    # 1. Panel never opened -> the poll must not be running at all.
    page.wait_for_timeout(_POLL_WINDOW_MS)
    assert not hits, (
        f"{api_path} was polled {len(hits)}x with {panel_id} closed -- the "
        f"activeOnly Poller is running when it should be inert"
    )

    # 2. Panel open -> the poll runs.
    _open_setup_panel(page, card_title)
    expect(page.locator(f"#{panel_id}")).to_be_visible()
    page.wait_for_timeout(_POLL_WINDOW_MS)
    while_open = len(hits)
    assert while_open >= 2, (
        f"{api_path} was polled only {while_open}x in {_POLL_WINDOW_MS}ms with "
        f"{panel_id} open -- expected an immediate poll plus at least one 5s tick"
    )

    # 3. Panel closed again -> the poll stops. Allow a moment for a request
    #    already in flight at close time to land before taking the baseline.
    _close_setup_panel(page, panel_id)
    page.wait_for_timeout(500)
    at_close = len(hits)
    page.wait_for_timeout(_POLL_WINDOW_MS)
    assert len(hits) == at_close, (
        f"{api_path} was polled {len(hits) - at_close}x more after {panel_id} "
        f"closed -- closePanel() did not stop the Poller"
    )


@_requires_browser
class TestPanelScopedPolling:
    def test_bluetooth_link_status_poll_is_panel_scoped(self, page: "Page", base_url: str):
        _assert_poll_is_panel_scoped(
            page, base_url, "/api/bluetooth/status", "Bluetooth", "panel-bluetooth"
        )

    def test_network_adapter_poll_is_panel_scoped(self, page: "Page", base_url: str):
        _assert_poll_is_panel_scoped(
            page, base_url, "/api/network/status", "System", "panel-system"
        )


