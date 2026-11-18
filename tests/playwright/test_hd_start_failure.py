"""Playwright tests for the HD page's "Could not start" card: shown for the
focused appliance, answered once for every view, behind the keypad, with
appliance text shown as text.

Like the other HD page tests these run against the production HdServer over
a FakeCore and check what the page sends on the wire. Without Playwright or
its pytest plugin they skip.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
from test_hd_dial import (  # noqa: E402,F401  (fixtures shared with the page smoke tests)
    _PLAYWRIGHT_INSTALLED, Watcher, browser_context_args, hd_server,
)
from test_hd_page_main import hd, open_page, watch_actions  # noqa: E402,F401

pytestmark = pytest.mark.skipif(not _PLAYWRIGHT_INSTALLED, reason="playwright not installed")

if _PLAYWRIGHT_INSTALLED:
    from playwright.sync_api import expect

import hd_scenarios as hs  # noqa: E402
from dial_core_state import StartFailureNotice  # noqa: E402

REFUSED = ("The speaker turned down the request to play. Check that it is switched on "
           "and not in use by another app, then try again.")


def notice(**fields):
    base = dict(appliance_id=hs.LOUNGE, key=hs.LOUNGE + ":boot-a:3", unit_id="o2", name="Patio",
                reason="refused", raised_at=hs.NOW - 1)
    base.update(fields)
    return StartFailureNotice(**base)


def failing(**fields):
    return hs.SCENARIOS["start_failure_refused"].with_snapshot(start_failure=notice(**fields))


def buttons(page):
    return page.locator("#card-buttons button")


class TestStartFailureCard:
    def test_the_card_names_the_speaker_and_the_reason(self, page, hd):
        hd.show(hs.SCENARIOS["start_failure_refused"])
        open_page(page, hd)
        expect(page.locator("#modal")).to_be_visible()
        expect(page.locator("#card-title")).to_have_text("Could not start Patio")
        expect(page.locator("#card-message")).to_have_text(REFUSED)
        assert buttons(page).all_text_contents() == ["OK"]

    def test_ok_posts_the_dismissal_once_and_closes_the_card(self, page, hd):
        sent = watch_actions(page)
        hd.show(hs.SCENARIOS["start_failure_refused"])
        open_page(page, hd)
        buttons(page).first.click()
        expect(page.locator("#modal")).to_be_hidden()
        assert sent == [("start_failure_dismiss", {"key": hs.LOUNGE + ":boot-a:3"})]
        # The dial may take a moment to drop it: the same key does not reopen the card.
        hd.show(hs.SCENARIOS["start_failure_refused"])
        page.wait_for_timeout(300)
        expect(page.locator("#modal")).to_be_hidden()
        assert len(sent) == 1

    def test_a_later_failure_shows_again(self, page, hd):
        hd.show(hs.SCENARIOS["start_failure_refused"])
        open_page(page, hd)
        buttons(page).first.click()
        expect(page.locator("#modal")).to_be_hidden()
        hd.show(failing(key=hs.LOUNGE + ":boot-a:4", name="Den"))
        expect(page.locator("#card-title")).to_have_text("Could not start Den")

    def test_a_reload_after_the_dial_dropped_it_shows_nothing(self, page, hd):
        hd.show(hs.SCENARIOS["start_failure_refused"])
        open_page(page, hd)
        buttons(page).first.click()
        hd.show(hs.SCENARIOS["playing_artwork"])
        page.reload()
        expect(page.locator("#title")).not_to_have_text("")
        expect(page.locator("#modal")).to_be_hidden()

    def test_another_appliances_failure_shows_nothing(self, page, hd):
        hd.show(hs.SCENARIOS["start_failure_elsewhere"])
        open_page(page, hd)
        expect(page.locator("#modal")).to_be_hidden()

    def test_the_keypad_goes_first_and_the_failure_follows_cancel(self, page, hd):
        pin = hs.SCENARIOS["pin_required"].with_snapshot(start_failure=notice())
        hd.show(pin)
        open_page(page, hd)
        expect(page.locator("#card.kind-pin")).to_be_visible()
        expect(page.locator("#card-title")).to_have_text("Enter PIN for Patio")
        page.locator("#card-buttons button", has_text="Cancel").click()
        expect(page.locator("#card-title")).to_have_text("Could not start Patio")

    def test_a_late_pin_request_opens_the_keypad_and_no_failure_card(self, page, hd):
        hd.show(hs.SCENARIOS["start_failure_late_pin"])
        open_page(page, hd)
        expect(page.locator("#card.kind-pin")).to_be_visible()
        expect(page.locator("#card-title")).to_have_text("Enter PIN for Patio")

    def test_a_name_with_markup_is_shown_as_text(self, page, hd):
        hd.show(failing(name="<b>Patio</b>"))
        open_page(page, hd)
        expect(page.locator("#card-title")).to_have_text("Could not start <b>Patio</b>")
        assert page.locator("#card-title b").count() == 0

    def test_an_unknown_reason_shows_the_fallback_sentence(self, page, hd):
        hd.show(failing(reason="mystery"))
        open_page(page, hd)
        expect(page.locator("#card-message")).to_have_text("The speaker did not start.")

    @pytest.mark.parametrize("reason,fragment", [
        ("failed", "autostream keeps trying while the music plays."),
        ("timed_out", "did not answer in time"),
        ("encoder_capacity", "cannot encode another stream"),
    ])
    def test_each_reason_has_its_sentence(self, page, hd, reason, fragment):
        hd.show(failing(reason=reason))
        open_page(page, hd)
        expect(page.locator("#card-message")).to_contain_text(fragment)
