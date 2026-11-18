"""Playwright tests: pages whose scripts are static files run as they did inline.

Each page is rendered by its real renderer and served with its script and
style files by the stub server. A class per page checks that it loads with no
script error, that it reads its data island, and that one thing it does at
load or on a click still happens.
"""
from __future__ import annotations

import hashlib
import re

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
    stub.API.clear()
    stub.REPLIES.clear()
    stub.POST_PATHS.clear()
    stub.POST_TOKENS.clear()


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


@_requires_browser
class TestAbout:
    def test_the_system_panel_fills_from_the_system_reply(self, page: "Page"):
        server, base = start_server(_page_stub.render("about"))
        try:
            errors = _watch_errors(page)
            stub.API["/api/about/system"] = {
                "ok": True, "builds": {"autostream": "9.9.9"}, "device": {"model": "Test Model"},
                "os": {"pretty_name": "Test OS"}, "playback_hours": 12.5, "services": []}
            page.goto(f"{base}/")
            expect(page.locator("#aboutBuildAutostream")).to_have_text("9.9.9")
            expect(page.locator("#aboutDeviceModel")).to_have_text("Test Model")
            expect(page.locator("#aboutPlaybackHours")).to_have_text("12.5 hours")
            assert errors == []
        finally:
            server.shutdown()

    def test_the_copy_button_copies_the_licence_text_from_the_island(self, page: "Page"):
        text = "Licence line one </script> & more"
        server, base = start_server(_page_stub.render("about", license_text=text))
        try:
            page.goto(f"{base}/")
            page.evaluate(
                "Object.defineProperty(navigator, 'clipboard', {configurable: true,"
                " value: {writeText: async function (t) { window.__copied = t; }}});")
            page.evaluate("openAboutPanel('license')")
            page.click("#copyLicenseBtn")
            expect(page.locator("#copyLicenseBtn")).to_have_text("Copied")
            assert page.evaluate("window.__copied") == text
        finally:
            server.shutdown()


@_requires_browser
class TestAlign:
    def test_start_shows_the_reason_the_server_gives(self, page: "Page"):
        server, base = start_server(_page_stub.render("align"))
        try:
            stub.REPLIES.append({"ok": False, "error": "output_ids must list at least two outputs"})
            page.goto(f"{base}/")
            page.click("#alignStartBtn")
            expect(page.locator("#alignStatus")).to_have_text(
                "Could not start: output_ids must list at least two outputs")
            assert stub.POST_PATHS == ["/api/align/start"]
        finally:
            server.shutdown()

    def test_the_status_poll_runs(self, page: "Page"):
        server, base = start_server(_page_stub.render("align"))
        try:
            page.goto(f"{base}/")
            _wait_for(page, lambda: "/api/align/status" in stub.PATHS, "the align status poll")
        finally:
            server.shutdown()


@_requires_browser
class TestService:
    def test_a_reset_button_posts_the_reset(self, page: "Page"):
        server, base = start_server(_page_stub.render("service"))
        try:
            page.goto(f"{base}/")
            page.evaluate("doServiceReset('stylus', 1)")
            page.wait_for_timeout(300)
            if page.locator("#svcConfirmModal.show").count():
                page.click("#svcConfirmOk")
            _wait_for(page, lambda: "/api/service/reset" in stub.POST_PATHS, "the reset post")
            assert stub.POSTS[-1] == {"item": "stylus", "input": 1}
        finally:
            server.shutdown()


@_requires_browser
class TestLogs:
    def test_saving_the_log_level_posts_it_with_the_page_token(self, page: "Page"):
        server, base = start_server(_page_stub.render("logs"))
        try:
            errors = _watch_errors(page)
            page.goto(f"{base}/")
            page.select_option("#log_level", index=1)
            level = page.input_value("#log_level")
            page.click("#logLevelSaveBtn")
            _wait_for(page, lambda: "/api/log-level" in stub.POST_PATHS, "the log level save")
            assert stub.POSTS[-1] == {"level": level}
            assert stub.POST_TOKENS[-1] == "t"
            assert errors == []
        finally:
            server.shutdown()


@_requires_browser
class TestOwntone:
    def test_a_visibility_toggle_posts_through_the_settings_transaction(self, page: "Page"):
        outputs = [{"id": "tv", "name": "Speaker A"}]
        server, base = start_server(_page_stub.render("owntone", outputs=outputs))
        try:
            errors = _watch_errors(page)
            page.goto(f"{base}/")
            assert page.evaluate("liveEnabled") is True
            expect(page.locator("#spk_settings_0")).to_be_visible()
            page.locator("input[name=show_0]").evaluate("el => el.click()")
            _wait_for(page, lambda: "/api/owntone/output-visibility" in stub.POST_PATHS,
                      "the visibility post")
            assert stub.POSTS[-1] == {"output_name": "Speaker A", "output_id": "tv", "visible": False}
            assert stub.POST_TOKENS[-1] == "t"
            expect(page.locator("#spk_settings_0")).to_be_hidden()
            assert errors == []
        finally:
            server.shutdown()


@_requires_browser
class TestRebooting:
    def test_the_countdown_starts_from_the_island_wait(self, page: "Page"):
        server, base = start_server(_page_stub.render("rebooting"))
        try:
            errors = _watch_errors(page)
            page.clock.install(time=0)
            page.goto(f"{base}/")
            _wait_for(page, lambda: "/api/reboot" in stub.POST_PATHS, "the reboot request")
            page.clock.run_for(1000)
            expect(page.locator("#status")).to_have_text("Reboot scheduled. Restarting in ~90s…")
            page.clock.run_for(59000)
            expect(page.locator("#status")).to_have_text("Reboot scheduled. Restarting in ~31s…")
            assert errors == []
        finally:
            server.shutdown()


@_requires_browser
class TestRestarting:
    def test_the_continue_link_and_redirect_use_the_island_path(self, page: "Page"):
        server, base = start_server(_page_stub.render("owntone_restarting", next_path="/setup?x=1"))
        try:
            errors = _watch_errors(page)
            stub.API["/api/owntone/ready"] = {"ok": False, "probe": "waiting"}
            page.goto(f"{base}/")
            expect(page.locator("#status")).to_have_text("Not ready yet. waiting")
            expect(page.locator("a")).to_have_attribute("href", "/setup?x=1")
            assert page.evaluate("pageData.next_path") == "/setup?x=1"
            stub.API["/api/owntone/ready"] = {"ok": True}
            page.wait_for_url(f"{base}/setup?x=1")
            assert errors == []
        finally:
            server.shutdown()

    def test_a_next_path_holding_a_script_end_tag_stays_text(self, page: "Page"):
        evil = "/a</script><script>window.__injected=1</script><b>x"
        server, base = start_server(_page_stub.render("owntone_restarting", next_path=evil))
        try:
            errors = _watch_errors(page)
            stub.API["/api/owntone/ready"] = {"ok": False}
            page.goto(f"{base}/")
            expect(page.locator("#status")).to_have_text("Not ready yet. ")
            assert page.evaluate("pageData.next_path") == evil
            assert page.evaluate("window.__injected") is None
            assert page.locator(".box b").count() == 0
            assert errors == []
        finally:
            server.shutdown()


@_requires_browser
class TestFirstBoot:
    @pytest.mark.parametrize("name", ["first_boot_owntone", "first_boot_appliance"])
    def test_both_pages_load_with_no_error(self, page: "Page", name: str):
        server, base = start_server(_page_stub.render(name))
        try:
            errors = _watch_errors(page)
            page.goto(f"{base}/")
            page.wait_for_load_state("networkidle")
            assert page.locator("body *").count() > 5
            assert errors == []
        finally:
            server.shutdown()


@_requires_browser
class TestAuth:
    def test_entering_a_pin_posts_a_proof_of_the_nonce_and_pin(self, page: "Page"):
        server, base = start_server(_page_stub.render("auth", next_path="/setup"))
        try:
            errors = _watch_errors(page)
            stub.REPLIES.append({"ok": True, "next": "/setup"})
            page.goto(f"{base}/")
            nonce = page.input_value("#nonce")
            assert nonce
            page.fill("#pin", "1234")
            page.press("#pin", "Enter")
            _wait_for(page, lambda: "/api/auth/verify" in stub.POST_PATHS, "the verify post")
            body = stub.POSTS[-1]
            assert body["nonce"] == nonce
            assert re.fullmatch(r"[0-9a-f]{64}", body["proof"])
            assert body["proof"] == hashlib.sha256((nonce + "1234").encode()).hexdigest()
            assert body["next"] == "/setup"
            page.wait_for_url(f"{base}/setup")
            assert errors == []
        finally:
            server.shutdown()

    def test_a_pin_the_server_would_refuse_reloads_with_the_error_and_posts_nothing(self, page: "Page"):
        server, base = start_server(_page_stub.render("auth", next_path="/setup"))
        try:
            page.goto(f"{base}/")
            page.fill("#pin", "12")
            page.press("#pin", "Enter")
            page.wait_for_url(re.compile(r"/auth\?next=%2Fsetup&err=1$"))
            assert stub.POST_PATHS == []
        finally:
            server.shutdown()
