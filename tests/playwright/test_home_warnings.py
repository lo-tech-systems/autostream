"""Playwright tests: the Home page shows what the appliance wants a person to know.

The page comes from the real Home renderer and the warnings part is pushed on
the stub's stream. Critical entries are the red banner (with "+N more" and a
tap that lists them all in place), every other entry is a card in the strip
above Now Playing (two cards, then "N more"; same-kind entries for several
inputs folded; a link and a chevron on the appliance's own page), and the
Service tab carries the worst severity of an entry that links to /service.
Everything follows the stream with no reload.
"""
from __future__ import annotations

import re

import pytest
import _home_stub as stub
from _home_stub import start_server
from _home_helpers import open_home, wait_stream, watch_errors

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


def entry(kind: str, severity: str = "warning", *, title: str | None = None, message: str | None = None,
          subject: str = "", link: str | None = None) -> dict:
    return {"id": f"{kind}_{subject or 'x'}", "incident": "", "severity": severity, "kind": kind,
            "subject": subject, "title": title or kind.title(), "message": message or f"{kind} message",
            "link": link}


def _warnings(*entries: dict) -> dict:
    return {"warnings": {"entries": list(entries)}}


PSU = entry("psu", "critical", title="Power supply", message="Undervoltage detected", link="/service")
SD = entry("sd_health", "critical", title="Storage", message="The SD card is failing")


@pytest.fixture(scope="module")
def home_url():
    server, url = start_server(b"")
    try:
        yield url
    finally:
        server.shutdown()


@pytest.fixture(autouse=True)
def _errors(page: "Page"):
    e = watch_errors(page)
    yield e
    stub.reset_stream()
    assert not e.left(), f"console errors: {e.left()}"


def _open(page: "Page", base: str, *entries: dict) -> None:
    open_home(page, base, _warnings(*entries))
    wait_stream(page, 200)


@_requires_browser
class TestBanner:
    def test_a_critical_entry_is_the_banner_on_first_render(self, page: "Page", home_url: str):
        _open(page, home_url, PSU)
        expect(page.locator("#red-banner")).to_have_text("Power supply: Undervoltage detected")
        expect(page.locator("#red-banner-spacer")).to_have_count(1)
        expect(page.locator("#warnings-strip .warning-card")).to_have_count(0)

    def test_it_appears_and_clears_with_no_reload(self, page: "Page", home_url: str):
        _open(page, home_url)
        expect(page.locator("#red-banner")).to_have_count(0)
        stub.push(_warnings(PSU))
        expect(page.locator("#red-banner")).to_have_text("Power supply: Undervoltage detected")
        stub.push(_warnings())
        expect(page.locator("#red-banner")).to_have_count(0)
        expect(page.locator("#red-banner-spacer")).to_have_count(0)

    def test_two_criticals_read_plus_one_more_and_a_tap_lists_both_in_place(self, page: "Page", home_url: str):
        _open(page, home_url, PSU, SD)
        banner = page.locator("#red-banner")
        expect(banner).to_have_text("Power supply: Undervoltage detected +1 more")
        banner.click()
        expect(banner.locator("div")).to_have_count(2)
        expect(banner).to_contain_text("Storage: The SD card is failing")
        expect(banner).not_to_contain_text("+1 more")
        banner.click()
        expect(banner).to_have_text("Power supply: Undervoltage detected +1 more")

    def test_a_single_critical_does_nothing_when_tapped(self, page: "Page", home_url: str):
        _open(page, home_url, PSU)
        page.locator("#red-banner").click()
        expect(page.locator("#red-banner")).to_have_text("Power supply: Undervoltage detected")

    def test_no_critical_entry_appears_in_the_strip(self, page: "Page", home_url: str):
        _open(page, home_url, PSU, SD, entry("cpu_temp", "warning"))
        expect(page.locator("#warnings-strip .warning-card")).to_have_count(1)
        expect(page.locator("#warnings-strip")).not_to_contain_text("Power supply")
        expect(page.locator("#warnings-strip")).not_to_contain_text("Storage")


@_requires_browser
class TestStrip:
    def test_the_strip_is_empty_and_hidden_without_entries(self, page: "Page", home_url: str):
        _open(page, home_url)
        expect(page.locator("#warnings-strip")).to_be_hidden()

    def test_a_card_has_a_bold_title_a_message_and_a_severity_border(self, page: "Page", home_url: str):
        _open(page, home_url, entry("cpu_temp", "warning", title="CPU temperature", message="Running hot"))
        card = page.locator("#warnings-strip .warning-card")
        expect(card).to_have_class("warning-card sev-warning")
        expect(card.locator(".warning-card-title")).to_have_text("CPU temperature")
        expect(card.locator(".warning-card-title")).to_have_css("font-weight", "700")
        expect(card.locator(".warning-card-msg")).to_have_text("Running hot")

    def test_two_cards_show_then_n_more_opens_the_rest_in_place(self, page: "Page", home_url: str):
        _open(page, home_url, entry("cpu_temp"), entry("sd_health"), entry("dials"))
        cards = page.locator("#warnings-strip .warning-card")
        expect(cards).to_have_count(2)
        more = page.locator("#warnings-strip .warning-more")
        expect(more).to_have_text("1 more")
        more.click()
        expect(cards).to_have_count(3)
        expect(more).to_have_count(0)

    def test_same_kind_entries_for_several_inputs_fold_into_one_card(self, page: "Page", home_url: str):
        _open(page, home_url,
              entry("stylus", subject="Turntable", message="Stylus wear is high"),
              entry("stylus", subject="Deck two", message="Stylus wear is high"))
        cards = page.locator("#warnings-strip .warning-card")
        expect(cards).to_have_count(1)
        expect(cards.locator(".warning-card-title")).to_have_text("Stylus")
        expect(cards.locator(".warning-card-msg")).to_have_text("Stylus wear is high on Turntable, Deck two")

    def test_a_card_with_a_link_is_a_link_with_a_chevron_and_one_without_is_not(self, page: "Page", home_url: str):
        _open(page, home_url, entry("belt", link="/service"), entry("dials"))
        linked = page.locator("#warnings-strip a.warning-card-link")
        expect(linked).to_have_count(1)
        expect(linked).to_have_attribute("href", "/service")
        expect(linked.locator(".warning-card-chevron")).to_have_text("›")
        expect(page.locator("#warnings-strip div.warning-card")).to_have_count(1)

    def test_a_card_follows_the_stream_with_no_reload(self, page: "Page", home_url: str):
        _open(page, home_url)
        stub.push(_warnings(entry("cpu_temp", "info", message="Warm")))
        expect(page.locator("#warnings-strip .warning-card.sev-info")).to_have_count(1)
        stub.push(_warnings())
        expect(page.locator("#warnings-strip .warning-card")).to_have_count(0)

    def test_nothing_can_be_dismissed(self, page: "Page", home_url: str):
        _open(page, home_url, entry("cpu_temp"))
        expect(page.locator("#warnings-strip button")).to_have_count(0)


@_requires_browser
class TestServiceTab:
    def test_its_class_follows_the_worst_service_severity(self, page: "Page", home_url: str):
        _open(page, home_url)
        tab = page.locator("#service-nav-tab")
        expect(tab).not_to_have_class(re.compile(r"nav-tab-warn"))
        stub.push(_warnings(entry("belt", "info", link="/service"), entry("bearing", "warning", link="/service")))
        expect(tab).to_have_class(re.compile(r"nav-tab-warn-warning"))
        stub.push(_warnings(entry("belt", "info", link="/service"), PSU))
        expect(tab).to_have_class(re.compile(r"nav-tab-warn-critical"))
        expect(tab).not_to_have_class(re.compile(r"nav-tab-warn-warning"))
        stub.push(_warnings(entry("dials", "critical", link="/setup#dials")))
        expect(tab).not_to_have_class(re.compile(r"nav-tab-warn"))
