"""Playwright tests: the Home speaker card says when a speaker is connecting or offline.

The page comes from the real Home renderer; the state parts and the intent
replies are stubbed. A speaker that is wanted but not yet playing reads
"Name (Connecting)", with its switch dimmed and still usable to turn it off.
The Auto-Start speaker's card while the player has no row for it reads
"Name (offline)": inside a session its switch is on and works, outside one it
is off and disabled. A change in the state moves the card without a reload.
"""
from __future__ import annotations

import re

import pytest
import _home_stub as stub
from _home_stub import start_server
from _home_helpers import intents, open_home, outputs, wait_for, wait_stream

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

_CONNECTING = re.compile(r"\boutput-card-connecting\b")
_OFFLINE = re.compile(r"\boutput-card-offline\b")
_LIVE = {"active": True, "source": "input1"}
_IDLE = {"active": False, "source": None}


def _unit(uid: str = "tv", **fields) -> dict:
    return stub.unit(uid, "Speaker A", **{"selected": True, "auto_start": True, **fields})


CONNECTING = _unit(connecting=True)
OFFLINE_IN_SESSION = _unit(offline=True)
OFFLINE_OUTSIDE_SESSION = _unit(offline=True, selected=False)
PLAYING = _unit()


@pytest.fixture
def serve():
    """Start the stub server; each is shut down after the test."""
    servers = []

    def start(page_bytes: bytes = b"") -> str:
        server, url = start_server(page_bytes)
        servers.append(server)
        return url

    yield start
    for server in servers:
        server.shutdown()


@pytest.fixture
def open_card(page: "Page", serve):
    """Open Home with one speaker row, in a session or not; the card is waited for."""
    url = serve()

    def open_(row: dict, session: dict = _LIVE) -> None:
        open_home(page, url, {"session": session, "outputs": outputs(row)}, wait_cards=False)
        page.wait_for_selector(f"#output_enabled_{row['id']}", state="attached")
        wait_stream(page, 200)

    return open_


def _tap(page: "Page") -> None:
    page.locator("#output_card_tv .output-toggle").click()


def _push(row: dict, session: dict = _LIVE) -> None:
    stub.push({"session": session, "outputs": outputs(row)})


@_requires_browser
class TestConnectingCard:
    def test_it_reads_connecting_with_a_dimmed_switch_that_still_works(self, page: "Page", open_card):
        open_card(CONNECTING)
        expect(page.locator("#output_card_tv")).to_have_class(_CONNECTING)
        expect(page.locator("#output_label_tv")).to_have_text("(Connecting)")
        expect(page.locator("#output_label_tv")).to_be_visible()
        expect(page.locator("#output_card_tv .output-toggle .switch")).to_have_css("opacity", "0.45")
        expect(page.locator("#output_enabled_tv")).to_be_checked()
        expect(page.locator("#output_enabled_tv")).to_be_enabled()

    def test_a_tap_turns_the_speaker_off(self, page: "Page", open_card):
        open_card(CONNECTING)
        _tap(page)
        wait_for(page, lambda: stub.POSTS, "the request")
        assert intents()[-1][0] == "outputs.set"
        assert intents()[-1][1]["id"] == "tv" and intents()[-1][1]["selected"] is False
        expect(page.locator("#output_label_tv")).to_be_hidden()
        expect(page.locator("#output_card_tv")).not_to_have_class(_CONNECTING)

    def test_a_change_that_has_it_playing_clears_the_label(self, page: "Page", open_card):
        open_card(CONNECTING)
        expect(page.locator("#output_label_tv")).to_have_text("(Connecting)")
        _push(PLAYING)
        expect(page.locator("#output_label_tv")).to_be_hidden()
        expect(page.locator("#output_card_tv")).not_to_have_class(_CONNECTING)
        expect(page.locator("#output_card_tv .output-toggle .switch")).to_have_css("opacity", "1")
        expect(page.locator("#output_enabled_tv")).to_be_checked()

    def test_a_change_that_has_it_connecting_sets_the_label(self, page: "Page", open_card):
        open_card(PLAYING)
        expect(page.locator("#output_label_tv")).to_be_hidden()
        _push(CONNECTING)
        expect(page.locator("#output_label_tv")).to_have_text("(Connecting)")
        expect(page.locator("#output_card_tv")).to_have_class(_CONNECTING)


@_requires_browser
class TestStoppingCard:
    STOPPING = _unit(selected=False, stopping=True)

    def test_a_speaker_switched_off_that_is_ending_its_session_reads_stopping(self, page: "Page", open_card):
        open_card(self.STOPPING)
        expect(page.locator("#output_label_tv")).to_have_text("(Stopping)")
        expect(page.locator("#output_card_tv")).to_have_class(_CONNECTING)
        expect(page.locator("#output_enabled_tv")).not_to_be_checked()
        expect(page.locator("#output_enabled_tv")).to_be_enabled()

    def test_the_label_clears_once_it_has_stopped(self, page: "Page", open_card):
        open_card(self.STOPPING)
        expect(page.locator("#output_label_tv")).to_have_text("(Stopping)")
        _push(_unit(selected=False))
        expect(page.locator("#output_label_tv")).to_be_hidden()
        expect(page.locator("#output_card_tv")).not_to_have_class(_CONNECTING)


@_requires_browser
class TestOfflineCard:
    def test_in_a_session_it_reads_offline_with_the_switch_on_and_working(self, page: "Page", open_card):
        open_card(OFFLINE_IN_SESSION)
        expect(page.locator("#output_card_tv")).to_have_class(_OFFLINE)
        expect(page.locator("#output_label_tv")).to_have_text("(offline)")
        expect(page.locator("#output_card_tv .output-toggle .switch")).to_have_css("opacity", "0.45")
        expect(page.locator("#output_enabled_tv")).to_be_checked()
        expect(page.locator("#output_enabled_tv")).to_be_enabled()
        expect(page.locator("#vol_slider_tv")).to_be_disabled()
        _tap(page)
        wait_for(page, lambda: stub.POSTS, "the request")
        assert intents()[-1][1]["id"] == "tv" and intents()[-1][1]["selected"] is False

    def test_outside_a_session_the_switch_is_off_and_disabled(self, page: "Page", open_card):
        open_card(OFFLINE_OUTSIDE_SESSION, _IDLE)
        expect(page.locator("#output_label_tv")).to_have_text("(offline)")
        expect(page.locator("#output_enabled_tv")).not_to_be_checked()
        expect(page.locator("#output_enabled_tv")).to_be_disabled()
        page.locator("#output_card_tv .output-toggle").click(force=True)
        page.wait_for_timeout(300)
        assert stub.POSTS == []

    def test_a_session_start_enables_the_switch(self, page: "Page", open_card):
        open_card(OFFLINE_OUTSIDE_SESSION, _IDLE)
        expect(page.locator("#output_enabled_tv")).to_be_disabled()
        _push(OFFLINE_IN_SESSION)
        expect(page.locator("#output_enabled_tv")).to_be_enabled()
        expect(page.locator("#output_enabled_tv")).to_be_checked()

    def test_the_card_becomes_a_normal_one_when_the_speaker_appears(self, page: "Page", open_card):
        open_card(OFFLINE_IN_SESSION)
        _push(_unit("real", connecting=True))
        page.wait_for_selector("#output_enabled_real", state="attached")
        expect(page.locator("#output_card_real")).to_have_class(_CONNECTING)
        expect(page.locator("#output_card_real")).not_to_have_class(_OFFLINE)
        expect(page.locator("#output_card_tv")).to_have_count(0)


PAUSED = _unit(held=True)


@_requires_browser
class TestPausedCard:
    def test_a_speaker_that_paused_itself_reads_paused_and_its_switch_turns_it_off(self, page: "Page", open_card):
        open_card(PAUSED)
        expect(page.locator("#output_state_tv")).to_have_text("Paused")
        expect(page.locator("#output_state_tv")).to_have_class(re.compile(r"\bpaused\b"))
        expect(page.locator("#output_label_tv")).to_be_hidden()
        expect(page.locator("#output_enabled_tv")).to_be_checked()
        _tap(page)
        wait_for(page, lambda: stub.POSTS, "the request")
        assert intents()[-1][1]["id"] == "tv" and intents()[-1][1]["selected"] is False

    def test_a_change_that_ends_the_pause_shows_it_on(self, page: "Page", open_card):
        open_card(PAUSED)
        expect(page.locator("#output_state_tv")).to_have_text("Paused")
        _push(PLAYING)
        expect(page.locator("#output_state_tv")).to_have_text("On")
