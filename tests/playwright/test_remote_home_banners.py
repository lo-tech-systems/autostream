"""Playwright tests: the remote Home page's warning banners follow its poll.

The remote (federated) Home page has its own renderer and poll: the three
maintenance banners show the warnings the poll carries, hide when one clears
and appear when one arrives without a reload.
"""
from __future__ import annotations

import sys

import pytest
import _home_stub as stub
from _home_stub import render_remote_home, start_server

sys.path.insert(0, str(stub.REPO_ROOT / "core"))
from autostream_input_status import SAMPLE_RATE_MISMATCH_BANNER_TEXT  # noqa: E402

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

_TEXTS = {
    "stylus": "Stylus wear is high: replace soon",
    "belt": "Belt service is due",
    "bearing": "Bearing service is due",
}


def _id(name: str) -> str:
    return f"#{name}-warning-banner"


def _text(name: str) -> str:
    return _TEXTS[name]


@pytest.fixture(autouse=True)
def _clean_stub():
    yield
    stub.REMOTE_HOME.clear()
    stub.REMOTE_HOME_POLLS.clear()



def _remote_home(warnings: dict) -> dict:
    return {"ok": True, "warnings": warnings}


@pytest.fixture(scope="module")
def remote_home_url():
    server, url = start_server(render_remote_home())
    try:
        yield url
    finally:
        server.shutdown()


@_requires_browser
class TestRemoteHomeBanners:
    def test_the_three_banners_show_the_polled_warnings(
        self, page: "Page", remote_home_url: str
    ):
        stub.set_page(render_remote_home())
        stub.REMOTE_HOME.update(_remote_home({n: _text(n) for n in list(_TEXTS)}))
        page.goto(f"{remote_home_url}/")
        for name in list(_TEXTS):
            expect(page.locator(_id(name))).to_be_visible(timeout=4000)
            expect(page.locator(_id(name))).to_have_text(_text(name))

    def test_a_banner_hides_when_its_warning_clears_and_the_others_stay(
        self, page: "Page", remote_home_url: str
    ):
        stub.set_page(render_remote_home())
        stub.REMOTE_HOME.update(_remote_home({n: _text(n) for n in list(_TEXTS)}))
        page.goto(f"{remote_home_url}/")
        expect(page.locator(_id("belt"))).to_be_visible(timeout=4000)
        stub.REMOTE_HOME["warnings"]["belt"] = ""
        expect(page.locator(_id("belt"))).to_be_hidden(timeout=8000)
        for name in ("stylus", "bearing"):
            expect(page.locator(_id(name))).to_be_visible()
            expect(page.locator(_id(name))).to_have_text(_text(name))

    def test_a_banner_appears_when_a_warning_arrives_after_the_first_poll(
        self, page: "Page", remote_home_url: str
    ):
        stub.set_page(render_remote_home())
        stub.REMOTE_HOME.update(_remote_home({n: "" for n in list(_TEXTS)}))
        page.goto(f"{remote_home_url}/")
        for _ in range(100):
            if stub.REMOTE_HOME_POLLS:
                break
            page.wait_for_timeout(100)
        expect(page.locator(_id("bearing"))).to_be_hidden()
        stub.REMOTE_HOME["warnings"]["bearing"] = _text("bearing")
        expect(page.locator(_id("bearing"))).to_be_visible(timeout=8000)
        expect(page.locator(_id("bearing"))).to_have_text(_text("bearing"))

    def test_only_the_maintenance_banners_exist_on_the_remote_page(
        self, page: "Page", remote_home_url: str
    ):
        stub.set_page(render_remote_home())
        stub.REMOTE_HOME.update(_remote_home({n: _text(n) for n in list(_TEXTS)}))
        page.goto(f"{remote_home_url}/")
        expect(page.locator(_id("stylus"))).to_be_visible(timeout=4000)
        for name in list(_TEXTS):
            expect(page.locator(_id(name))).to_have_count(1)
        expect(page.locator("#dial-update-warning-banner")).to_have_count(0)
        expect(page.locator("#sample-rate-warning-banner")).to_have_count(0)

    def test_a_sample_rate_warning_in_the_payload_is_ignored(
        self, page: "Page", remote_home_url: str
    ):
        errors: list = []
        page.on("pageerror", lambda e: errors.append(str(e)))
        stub.set_page(render_remote_home())
        warnings = {n: _text(n) for n in list(_TEXTS)}
        warnings["sample_rate"] = SAMPLE_RATE_MISMATCH_BANNER_TEXT
        stub.REMOTE_HOME.update(_remote_home(warnings))
        page.goto(f"{remote_home_url}/")
        expect(page.locator(_id("stylus"))).to_be_visible(timeout=4000)
        for _ in range(100):
            if len(stub.REMOTE_HOME_POLLS) >= 2:
                break
            page.wait_for_timeout(100)
        expect(page.locator("#sample-rate-warning-banner")).to_have_count(0)
        expect(page.get_by_text(SAMPLE_RATE_MISMATCH_BANNER_TEXT)).to_have_count(0)
        assert not errors, f"JavaScript errors: {errors}"
