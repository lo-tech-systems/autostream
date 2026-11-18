"""Playwright tests: pages whose scripts are static files run as they did inline.

Each page is rendered by its real renderer and served with its script and
style files by the stub server. A class per page checks that it loads with no
script error, that it reads its data island, and that one thing it does at
load or on a click still happens.
"""
from __future__ import annotations

import pytest
import _home_stub as stub
import _page_stub
from _home_stub import render_home, render_remote_home, start_server

try:
    from playwright.sync_api import Page, expect  # type: ignore[attr-defined]
    _PLAYWRIGHT_INSTALLED = True
except ImportError:
    _PLAYWRIGHT_INSTALLED = False
    Page = object  # type: ignore[misc,assignment]
    expect = None  # type: ignore[assignment]

_requires_browser = pytest.mark.skipif(
    not _PLAYWRIGHT_INSTALLED, reason="playwright not installed"
)


def _watch_errors(page: "Page") -> list:
    """Collect uncaught script errors and console errors from ``page``."""
    errors: list = []
    page.on("pageerror", lambda exc: errors.append(f"pageerror: {exc}"))
    page.on(
        "console",
        lambda msg: errors.append(f"console: {msg.text}") if msg.type == "error" else None,
    )
    return errors


@pytest.fixture(autouse=True)
def _clean_stub():
    yield
    stub.STATUS.clear()
    stub.STATUS_POLLS.clear()
    stub.OUTPUTS.clear()
    stub.POLLS.clear()
    stub.REMOTE_HOME.clear()
    stub.REMOTE_HOME_POLLS.clear()
    stub.POSTS.clear()
    stub.PATHS.clear()


def _wait_for(page: "Page", done, what: str) -> None:
    for _ in range(100):
        if done():
            return
        page.wait_for_timeout(100)
    raise AssertionError(f"timed out waiting for {what}")


@_requires_browser
class TestHome:
    def test_loads_with_no_error_and_reads_its_island(self, page: "Page"):
        server, base = start_server(render_home())
        try:
            errors = _watch_errors(page)
            stub.STATUS.update({"ok": True})
            page.goto(f"{base}/")
            _wait_for(page, lambda: stub.POLLS, "the first speaker list poll")
            assert errors == []
            assert page.evaluate("window.__OUTPUT_URL") == "/api/output"
            assert page.evaluate("window.__REPEAT_URL") == "/api/repeat"
            assert page.evaluate("window.__OUTPUTS_EMPTY_TOLERANCE_MS") == 6000
            assert page.evaluate("window.__PRESET_VOLUME") == 20
            assert page.evaluate("window.__ICON_CD").startswith("<svg")
        finally:
            server.shutdown()

    def test_the_remote_page_loads_its_file_and_polls_once(self, page: "Page"):
        server, base = start_server(render_remote_home())
        try:
            errors = _watch_errors(page)
            stub.REMOTE_HOME.update({"ok": True, "warnings": {}})
            page.goto(f"{base}/")
            _wait_for(page, lambda: stub.REMOTE_HOME_POLLS, "the remote home poll")
            assert errors == []
            assert page.evaluate("window.__POLL_URL") == (
                f"/api/appliances/{stub.REMOTE_APPLIANCE_ID}/home")
            assert page.evaluate("window.__REMOTE_AID") == stub.REMOTE_APPLIANCE_ID
        finally:
            server.shutdown()


@_requires_browser
class TestEqualiser:
    def test_loads_with_no_error_and_draws_the_curve(self, page: "Page"):
        server, base = start_server(_page_stub.render("equaliser"))
        try:
            errors = _watch_errors(page)
            page.goto(f"{base}/")
            assert page.locator("#eq-curve-path").get_attribute("d").startswith("M")
            assert errors == []
        finally:
            server.shutdown()

    def test_moving_a_band_slider_redraws_the_curve_and_posts_once(self, page: "Page"):
        server, base = start_server(_page_stub.render("equaliser"))
        try:
            page.goto(f"{base}/")
            before = page.locator("#eq-curve-path").get_attribute("d")
            stub.POSTS.clear()
            page.evaluate(
                "var s = document.getElementById('peq3_db'); s.value = '6';"
                " s.dispatchEvent(new Event('input', {bubbles: true}));")
            assert page.locator("#eq-curve-path").get_attribute("d") != before
            _wait_for(page, lambda: stub.POSTS, "the equaliser save")
            page.wait_for_timeout(1000)
            assert len(stub.POSTS) == 1
        finally:
            server.shutdown()

    def test_the_remote_page_polls_its_state_url(self, page: "Page"):
        server, base = start_server(_page_stub.render("remote_equaliser"))
        try:
            page.goto(f"{base}/")
            poll = f"/api/appliances/{stub.REMOTE_APPLIANCE_ID}/equaliser"
            _wait_for(page, lambda: poll in stub.PATHS, "the remote equaliser poll")
            assert page.evaluate("window.__POLL_URL") == poll
        finally:
            server.shutdown()
