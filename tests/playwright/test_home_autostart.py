"""Playwright tests: the Auto-Start pin on Home.

The page comes from the real Home renderer; the state parts and the intent
replies are stubbed. The pin icon (no text) shows during a session and is set
while the speakers on are the saved set (the part's ``default_matches``). A tap
opens the confirmation; Yes sends ``outputs.save_default``, Cancel and Escape
send nothing, and a refusal says why. Speakers in the set carry an
"Auto-Start" pill.
"""
from __future__ import annotations

import re

import pytest
import _home_stub as stub
from _home_stub import start_server
from _home_helpers import SHOWN, intents, open_home, outputs, speaker, wait_stream, watch_errors

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

_LIVE = {"active": True, "source": "input1"}
_IDLE = {"active": False, "source": None}
_CONFIRM = "Auto-Start playing for future sessions with the current playing devices?"


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


def _open(page: "Page", base: str, *, session: dict = _LIVE, matches: bool = False) -> None:
    open_home(page, base, {"session": session,
                           "outputs": outputs(speaker(selected=True), default_matches=matches)})
    wait_stream(page, 200)


@_requires_browser
class TestPinIcon:
    def test_it_shows_during_a_session_and_not_outside_one(self, page: "Page", home_url: str):
        _open(page, home_url, session=_IDLE)
        expect(page.locator("#autostart-pin")).to_be_hidden()
        stub.push({"session": _LIVE})
        expect(page.locator("#autostart-pin")).to_be_visible()
        stub.push({"session": _IDLE})
        expect(page.locator("#autostart-pin")).to_be_hidden()

    def test_it_is_an_icon_with_no_text(self, page: "Page", home_url: str):
        _open(page, home_url)
        pin = page.locator("#autostart-pin")
        expect(pin).to_have_text("")
        expect(pin.locator("svg")).to_have_count(1)
        expect(pin).to_have_attribute("aria-label", "Auto-Start these speakers")

    def test_it_is_set_while_the_speakers_match_the_saved_set_and_follows_the_part(
        self, page: "Page", home_url: str
    ):
        _open(page, home_url)
        pin = page.locator("#autostart-pin")
        expect(pin).to_have_attribute("aria-pressed", "false")
        expect(pin).not_to_have_class(re.compile(r"\bis-set\b"))
        stub.push({"outputs": outputs(speaker(selected=True), default_matches=True)})
        expect(pin).to_have_attribute("aria-pressed", "true")
        expect(pin).to_have_class(re.compile(r"\bis-set\b"))
        stub.push({"outputs": outputs(speaker(selected=True), default_matches=False)})
        expect(pin).to_have_attribute("aria-pressed", "false")

    def test_without_master_volume_it_sits_right_aligned_directly_above_the_speaker_list(
        self, page: "Page", home_url: str
    ):
        _open(page, home_url)
        expect(page.locator(".autostart-row #autostart-pin")).to_have_count(1)
        expect(page.locator("#autostart-pin")).to_have_count(1)
        pin = page.locator("#autostart-pin").bounding_box()
        lst = page.locator("#outputs-list").bounding_box()
        vp = page.viewport_size["width"]
        assert pin["y"] < lst["y"] and lst["y"] - (pin["y"] + pin["height"]) < 60
        assert pin["x"] + pin["width"] > vp * 0.7

    @pytest.mark.parametrize("input_detail", [False, True], ids=["no_meters", "with_meters"])
    def test_with_master_volume_it_sits_at_the_right_of_the_volume_header(
        self, page: "Page", home_url: str, input_detail: bool
    ):
        open_home(page, home_url, {"session": _LIVE, "outputs": outputs(speaker(selected=True))},
                  show_master_volume=True, show_input_detail=input_detail)
        wait_stream(page, 200)
        pin = page.locator("#master-volume-card .slider-header #autostart-pin")
        expect(pin).to_have_count(1)
        expect(page.locator("#autostart-pin")).to_have_count(1)
        expect(page.locator(".autostart-row")).to_have_count(0)
        expect(pin).to_be_visible()
        box, card = pin.bounding_box(), page.locator("#master-volume-card").bounding_box()
        rem = page.evaluate("parseFloat(getComputedStyle(document.documentElement).fontSize)")
        assert round(box["width"]) == round(box["height"]) == round(2 * rem)
        assert abs((card["x"] + card["width"]) - (box["x"] + box["width"])) <= 1
        assert page.locator("#master-volume-card .slider-header span").bounding_box()["x"] < box["x"]
        if input_detail:
            level = page.locator("#np-level").bounding_box()
            assert abs((level["x"] + level["width"]) - (box["x"] + box["width"])) <= 1
        pin.click()
        expect(page.locator("#autoStartModal")).to_have_class(SHOWN)


@_requires_browser
class TestConfirmation:
    def test_a_tap_opens_the_confirmation_with_its_text_every_time(self, page: "Page", home_url: str):
        _open(page, home_url)
        modal = page.locator("#autoStartModal")
        for _ in range(2):
            page.locator("#autostart-pin").click()
            expect(modal).to_have_class(SHOWN)
            expect(page.locator("#autoStartText")).to_have_text(_CONFIRM)
            page.locator("#autoStartCancel").click()
            expect(modal).not_to_have_class(SHOWN)

    def test_cancel_and_escape_send_nothing(self, page: "Page", home_url: str):
        _open(page, home_url)
        page.locator("#autostart-pin").click()
        page.locator("#autoStartCancel").click()
        page.locator("#autostart-pin").click()
        page.keyboard.press("Escape")
        expect(page.locator("#autoStartModal")).not_to_have_class(SHOWN)
        page.wait_for_timeout(300)
        assert stub.POSTS == []

    def test_yes_sends_save_default_and_the_icon_follows_the_part_not_the_reply(
        self, page: "Page", home_url: str
    ):
        _open(page, home_url)
        page.locator("#autostart-pin").click()
        page.locator("#autoStartYes").click()
        expect(page.locator("#autoStartModal")).not_to_have_class(SHOWN)
        page.wait_for_timeout(500)
        assert intents() == [("outputs.save_default", {})]
        expect(page.locator("#autostart-pin")).not_to_have_class(re.compile(r"\bis-set\b"))
        stub.push({"outputs": outputs(speaker(selected=True), default_matches=True)})
        expect(page.locator("#autostart-pin")).to_have_class(re.compile(r"\bis-set\b"))

    @pytest.mark.parametrize("error,text", [
        ("nothing_selected", "Turn on at least one speaker first."),
        ("settings_unavailable", "The speakers could not be saved just now. Try again in a moment."),
    ])
    def test_a_refusal_says_why(self, page: "Page", home_url: str, error: str, text: str):
        _open(page, home_url)
        stub.REPLIES[:] = [{"ok": False, "error": error, "result": {"error": error}}]
        page.locator("#autostart-pin").click()
        page.locator("#autoStartYes").click()
        expect(page.locator("#infoModal")).to_have_class(SHOWN)
        expect(page.locator("#infoModalMessage")).to_have_text(text)


@_requires_browser
class TestPill:
    def test_a_speaker_in_the_set_carries_the_auto_start_pill_and_one_outside_it_does_not(
        self, page: "Page", home_url: str
    ):
        open_home(page, home_url, {"outputs": outputs(
            stub.unit("tv", "Speaker A", auto_start=True), stub.unit("hp", "Speaker B"))})
        expect(page.locator("#output_card_tv .output-card-default")).to_be_visible()
        expect(page.locator("#output_card_tv .output-card-default")).to_have_text("Auto-Start")
        expect(page.locator("#output_card_hp .output-card-default")).to_be_hidden()

    def test_cards_in_the_set_come_first(self, page: "Page", home_url: str):
        open_home(page, home_url, {"outputs": outputs(
            stub.unit("tv", "Zed", auto_start=True), stub.unit("hp", "Alpha"))})
        ids = page.eval_on_selector_all(".output-card", "els => els.map(e => e.getAttribute('data-output-id'))")
        assert ids == ["tv", "hp"]
