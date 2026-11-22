"""Playwright end-to-end browser tests.

Covers: page rendering, navigation cards, panel interaction, accessibility.

The stub server started by the ``base_url`` fixture serves HTML produced by
the real ``send_setup_page()`` renderer (core/webui/browser/setup/page.py)
through ``_page_stub``, with hardware dependencies mocked out.  Changes to the
page template, its embedded CSS, or its JavaScript therefore break these tests,
not just changes to hand-written HTML.

When AUTOSTREAM_URL is set the tests run against a real appliance instead.

Requirements:
  pip install pytest-playwright && playwright install chromium

CI job: playwright in .github/workflows/ci.yml.
"""
from __future__ import annotations

import json
import os
import re
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

import _page_stub

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


# ---------------------------------------------------------------------------
# Stub HTTP server
# ---------------------------------------------------------------------------

# Populated once per session by the base_url fixture before the server starts.
_STUB_HTML_BYTES: bytes = b""
# Keyed by card key, each value is the JSON body handle_setup_card_get()
# produced for that card ({"ok": true, "html": "..."}), pre-rendered once so
# the stub server can answer the browser's lazy per-card fetch.
_STUB_CARD_JSON: dict = {}

_RATE_MATCHING_NOTE_STUB = "Stub note for input {index}."


def _stub_levels_reply() -> dict:
    """The state body the stub serves for the Setup level readout (the inputs
    and monitor parts); a test edits it between polls. Input 2 is not running,
    so it has no entry."""
    return {
        "ok": True,
        "parts": {
            "monitor": {"connected": True},
            "inputs": {"entries": [
                {"index": 1, "device": "hw:1,0", "input_type": "turntable", "capturing": True,
                 "replay_origin": False,
                 "rate_note": _RATE_MATCHING_NOTE_STUB.format(index=1),
                 "sample_rate_text": "Sample rate: 48 kHz", "rate_mismatch_hz": 0,
                 "level": {"index": 1, "dbfs": -52.0}},
            ]},
        },
    }


# Mutable stub state, reset by a fixture before each test that uses it.
_STUB_LEVELS: dict = _stub_levels_reply()
# Bodies of the JSON POSTs the stub has received, oldest first.
_STUB_POSTS: list = []


class _StubHandler(BaseHTTPRequestHandler):
    """Serve production-rendered HTML for page requests and JSON stubs for /api/."""

    def do_GET(self) -> None:
        if self.path.startswith("/static/"):
            _page_stub.serve_static(self, self.path)
            return
        if self.path.startswith("/api/setup/card/"):
            # Lazy per-card detail fetch: serve the pre-rendered
            # {ok, html} body for this specific card, not the generic
            # catch-all below (which has no "html" key and would leave
            # every panel showing the client's load-failure fallback).
            key = self.path.rsplit("/", 1)[-1]
            body = _STUB_CARD_JSON.get(key, b'{"ok": false, "error": "unknown_card"}')
            ct = "application/json"
        elif self.path.startswith("/api/v1/state"):
            body = json.dumps(_STUB_LEVELS).encode("utf-8")
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

    def do_POST(self) -> None:
        """Record the JSON body and answer as the settings route does on success."""
        length = int(self.headers.get("Content-Length", "0"))
        posted = json.loads(self.rfile.read(length) or b"{}")
        _STUB_POSTS.append(posted)
        body = json.dumps({
            "ok": True,
            "field": posted.get("field"),
            "value": posted.get("value"),
            "live": True,
        }).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
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
    _STUB_HTML_BYTES = _page_stub.render("setup", bt_enabled=True)
    _STUB_CARD_JSON = _page_stub.setup_card_json(bt_enabled=True)

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
# core/webui/browser/setup/ exactly.
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
        """The Setup page reads the state every 2 s; the stub returns valid JSON."""
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

        _open_setup_panel(page, "Input 2")
        expect(page.locator("#panel-input2")).to_be_visible()
        _close_setup_panel(page, "panel-input2")
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
            page, base_url, "/api/bluetooth/status", "Input 3 (Bluetooth)", "panel-input3"
        )

    def test_network_adapter_poll_is_panel_scoped(self, page: "Page", base_url: str):
        _assert_poll_is_panel_scoped(
            page, base_url, "/api/network/status", "System", "panel-system"
        )

    def test_input_levels_poll_is_panel_scoped(self, page: "Page", base_url: str):
        _assert_poll_is_panel_scoped(
            page, base_url, "/api/v1/state?parts=inputs,monitor", "Input 1", "panel-input1"
        )


# ---------------------------------------------------------------------------
# Input card: type select, sensitivity slider and level readout.
# ---------------------------------------------------------------------------

@_requires_browser
class TestInputTypeAndSensitivity:
    @pytest.fixture(autouse=True)
    def _fresh_stub_state(self):
        _STUB_LEVELS.clear()
        _STUB_LEVELS.update(_stub_levels_reply())
        _STUB_POSTS.clear()

    def _open_input1(self, page: "Page", base_url: str) -> None:
        page.goto(f"{base_url}/setup")
        _open_setup_panel(page, "Input 1")
        expect(page.locator("#panel-input1")).to_be_visible()

    def test_controls_present(self, page: "Page", base_url: str):
        self._open_input1(page, base_url)
        expect(page.locator("#audio1_input_type")).to_be_visible()
        expect(page.locator("#audio_silence_threshold")).to_be_visible()
        expect(page.locator("#audio1_level_val")).to_be_visible()

    def test_type_change_moves_slider_to_preset(self, page: "Page", base_url: str):
        self._open_input1(page, base_url)
        label = page.locator("#audio1_silence_threshold_val")
        slider = page.locator("#audio_silence_threshold")
        page.select_option("#audio1_input_type", "turntable")
        expect(label).to_have_text("-45 dB")
        assert slider.input_value() == "-45"
        page.select_option("#audio1_input_type", "cd")
        expect(label).to_have_text("-60 dB")
        assert slider.input_value() == "-60"
        # CD and Line share a preset, so a tuned value survives the switch.
        slider.evaluate(
            "el => { el.value = '-55'; el.dispatchEvent(new Event('input', {bubbles: true})); }"
        )
        page.select_option("#audio1_input_type", "line")
        expect(label).to_have_text("-55 dB")
        assert slider.input_value() == "-55"

    def test_slider_label_follows(self, page: "Page", base_url: str):
        self._open_input1(page, base_url)
        page.locator("#audio_silence_threshold").evaluate(
            "el => { el.value = '-55'; el.dispatchEvent(new Event('input', {bubbles: true})); }"
        )
        expect(page.locator("#audio1_silence_threshold_val")).to_have_text("-55 dB")

    def test_level_readout(self, page: "Page", base_url: str):
        self._open_input1(page, base_url)
        slider = page.locator("#audio_silence_threshold")
        slider.evaluate(
            "el => { el.value = '-60'; el.dispatchEvent(new Event('input', {bubbles: true})); }"
        )
        expect(page.locator("#audio1_level_val")).to_have_text(
            "-52 dB (above threshold)", timeout=3000
        )
        # Raising the threshold above the level drops the mark at once.
        slider.evaluate(
            "el => { el.value = '-40'; el.dispatchEvent(new Event('input', {bubbles: true})); }"
        )
        expect(page.locator("#audio1_level_val")).to_have_text("-52 dB")
        page.locator("#panel-input1 .setup-detail-back button").click()
        _open_setup_panel(page, "Input 2")
        expect(page.locator("#panel-input2")).to_be_visible()
        expect(page.locator("#audio2_level_val")).to_have_text("no level")

    def test_rate_matching_switch_saves_through_the_settings_route(
        self, page: "Page", base_url: str
    ):
        if os.environ.get("AUTOSTREAM_URL"):
            pytest.skip("posts a setting to the stub; not for a real appliance")
        self._open_input1(page, base_url)
        switch = page.locator("#audio1_dynamic_rate_matching")
        expect(switch).to_be_attached()
        assert switch.is_checked()
        page.locator("#panel-input1 label.output-toggle:has(#audio1_dynamic_rate_matching)").click()
        expect(page.locator("#autosave-status")).to_have_text("Saved")
        assert not switch.is_checked()
        assert _STUB_POSTS == [{"field": "audio1.dynamic_rate_matching", "value": False}]

    def test_rate_matching_note_follows_the_levels_reply_without_a_reload(
        self, page: "Page", base_url: str
    ):
        if os.environ.get("AUTOSTREAM_URL"):
            pytest.skip("edits the stub's levels reply; not for a real appliance")
        self._open_input1(page, base_url)
        note = page.locator("#audio1_rate_matching_note")
        expect(note).to_have_text("Stub note for input 1.", timeout=3000)
        _STUB_LEVELS["parts"]["inputs"]["entries"][0]["rate_note"] = "Changed while the card was open."
        expect(note).to_have_text("Changed while the card was open.", timeout=3000)
        expect(page.locator("#panel-input1")).to_be_visible()

    def test_sample_rate_line_follows_the_levels_reply_without_a_reload(
        self, page: "Page", base_url: str
    ):
        if os.environ.get("AUTOSTREAM_URL"):
            pytest.skip("edits the stub's levels reply; not for a real appliance")
        self._open_input1(page, base_url)
        line = page.locator("#audio1_sample_rate")
        expect(line).to_have_text("Sample rate: 48\u00a0kHz", timeout=3000)
        _STUB_LEVELS["parts"]["inputs"]["entries"][0]["sample_rate_text"] = (
            "Sample rate: 44.1\u00a0kHz (device opened at 48\u00a0kHz)"
        )
        expect(line).to_have_text(
            "Sample rate: 44.1\u00a0kHz (device opened at 48\u00a0kHz)", timeout=3000
        )
        expect(page.locator("#panel-input1")).to_be_visible()




@_requires_browser
class TestInputDeepLinks:
    """The hash the Home page sample rate banner links to opens that input's card."""

    @pytest.mark.parametrize("n, other", [(1, 2), (2, 1)])
    def test_the_hash_opens_that_inputs_card(
        self, page: "Page", base_url: str, n: int, other: int
    ):
        page.goto(f"{base_url}/setup#input{n}")
        expect(page.locator(f"#panel-input{n}")).to_be_visible()
        expect(page.locator(f"#panel-input{n}")).to_have_class(
            re.compile(r"\bactive\b")
        )
        expect(page.locator(f"#audio{n}_dynamic_rate_matching")).to_be_attached()
        expect(page.locator(f"#panel-input{other}")).not_to_have_class(
            re.compile(r"\bactive\b")
        )
